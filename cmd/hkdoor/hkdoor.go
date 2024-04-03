// command hkdoor serves a homekit accessory that controls a door buzzer using
// relays on a sequent i2c card.
//
// it can also proxy garage door commands to an ismartgate controller.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"log"
	"math/rand"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"time"

	"github.com/brutella/hap"
	"github.com/brutella/hap/accessory"
	"github.com/brutella/hap/service"
	"periph.io/x/conn/v3/i2c"
	"periph.io/x/conn/v3/i2c/i2creg"
	"periph.io/x/host/v3"
)

const (
	card           = 1 // The index of the sequent card in the stack.
	doorEastRelay  = 0 // The index of the relay used for the first door.
	doorSouthRelay = 1 // The index of the relay used for the second door.
	gateEastAddr   = "192.168.100.52"
	gateSouthAddr  = "192.168.100.70"
)

func buzz(r int) {
	setRelay(r, true)
	go func() {
		time.Sleep(1 * time.Second)
		setRelay(r, false)
	}()
}

var doors = []any{}

func main() {
	log.SetFlags(0)
	log.SetPrefix("")
	pin := flag.String("pin", "", "homekit pin")
	addr := flag.String("addr", ":0", "listen address")
	gateUsername := flag.String("username", "", "username ismartgate controllers")
	gatePassword := flag.String("password", "", "password for ismartgate controllers")
	enableGates := flag.Bool("gates", false, "enable gates")

	statedir := flag.String("state", filepath.Join(os.Getenv("HOME"), "hk", filepath.Base(os.Args[0])), "state directory")
	flag.Parse()

	if _, err := host.Init(); err != nil {
		log.Fatalf("could not init i2c: %v", err)
	}

	b, err := i2creg.Open("")
	if err != nil {
		log.Fatalf("could not open i2c device: %v", err)
	}
	relay.Dev = &i2c.Dev{Addr: deviceAddress + (0x07 ^ card), Bus: b}

	setRelay(0, false)
	setRelay(1, false)
	setRelay(2, false)
	setRelay(3, false)

	id, err := os.ReadFile(path.Join(*statedir, "id"))
	if errors.Is(err, os.ErrNotExist) {
		n := rand.Int63n(10000)
		id = strconv.AppendInt(id, n, 10)
		err := os.MkdirAll(*statedir, 0755)
		if err != nil {
			log.Fatalf("could not make state dir: %v", err)
		}
		err = os.WriteFile(path.Join(*statedir, "id"), id, 0644)
		if err != nil {
			log.Fatalf("could not create unique name: %v", err)
		}
	}

	bridge := accessory.NewBridge(accessory.Info{Name: "doors-" + string(id), Manufacturer: "aljammaz labs", SerialNumber: string(id)}).A
	bridge.Id = 1

	var as []*accessory.A
	eastdoor := newDoor("east", doorEastRelay)
	southdoor := newDoor("south", doorSouthRelay)
	doors = append(doors, eastdoor, southdoor)
	as = append(as, eastdoor.a, southdoor.a)
	if *enableGates {
		eastgate := newGate("east gate", gateEastAddr, *gateUsername, *gatePassword)
		southgate := newGate("south gate", gateSouthAddr, *gateUsername, *gatePassword)
		doors = append(doors, eastgate, southgate)
		as = append(as, eastgate.a, southgate.a)
	}

	for i := range as {
		as[i].Id = uint64(i + 2)
	}

	server, err := hap.NewServer(hap.NewFsStore(*statedir), bridge, as...)
	if err != nil {
		log.Fatalf("could not make hap server: %v", err)
	}

	server.ServeMux().HandleFunc("/resource", handleResource)
	server.Pin = *pin
	server.Addr = *addr
	log.Fatal(server.ListenAndServe(context.Background()))
}

func handleResource(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "unexpected method", http.StatusBadRequest)
		return
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		log.Printf("/resource: could not read body: %v", err)
		http.Error(w, "could not read body", http.StatusInternalServerError)
		return
	}

	msg := struct {
		AID    int    `json:"aid"`
		Type   string `json:"resource-type"`
		Width  int    `json:"image-width"`
		Height int    `json:"image-height"`
	}{}

	err = json.Unmarshal(body, &msg)
	if err != nil {
		log.Printf("/resource: could not parse body: %v", err)
		http.Error(w, "could not read body", http.StatusInternalServerError)
		return
	}

	// ID 1 is the bridge
	// IDs 2 onwards are our devices
	index := msg.AID - 2
	if !(0 <= index && index < len(doors)) {
		log.Printf("/resource: unknown accessory id: %v", msg.AID)
		http.Error(w, "unexpected id", http.StatusBadRequest)
		return
	}

	switch msg.Type {
	case "open":
		switch d := doors[index].(type) {
		case *door:
			d.updateLock(0)
			log.Printf("%s: opening for %s", d.name, r.RemoteAddr)
		case *gate:
			d.toggle()
			log.Printf("%s: opening for %s", d.name, r.RemoteAddr)
		}
	default:
		log.Printf("/resource: unexpected type: %v", msg.Type)
		http.Error(w, "unexpected type", http.StatusBadRequest)
		return
	}
}

type door struct {
	// name is this door's name.
	name string
	// relay is the index of the this door's relay.
	relay int
	// the hap package's service object.
	lock *service.LockMechanism

	a *accessory.A
}

func newDoor(name string, relay int) *door {
	d := &door{
		name:  name,
		relay: relay,
		a: accessory.New(accessory.Info{
			Name:         name,
			Manufacturer: "aljammaz labs",
		}, accessory.TypeDoorLock),
		lock: service.NewLockMechanism(),
	}

	// lock
	// initialise to closed.
	d.lock.LockCurrentState.SetValue(1)
	d.lock.LockTargetState.SetValue(1)
	d.lock.LockTargetState.OnValueRemoteUpdate(d.updateLock)
	d.a.AddS(d.lock.S)

	return d
}

func (d *door) updateLock(v int) {
	switch v {
	case 0:
		// Unsecured
		log.Printf("opening door: %v", d.name)
		buzz(d.relay)
		d.lock.LockCurrentState.SetValue(0)
		go func() {
			time.Sleep(2 * time.Second)
			d.lock.LockTargetState.SetValue(1)
			d.lock.LockCurrentState.SetValue(1)
		}()
	case 1:
		// Secured
		log.Printf("securing door: %v", d.name)
		setRelay(d.relay, false)
		d.lock.LockTargetState.SetValue(1)
		d.lock.LockCurrentState.SetValue(1)
	default:
		log.Printf("unknown lock state: %v", v)
	}
}

const (
	gateOpened = 0
	gateClosed = 1
)

type gate struct {
	// name is this gates's name.
	name string

	// for the ismartgate api.
	addr, username, password string

	g *service.GarageDoorOpener
	a *accessory.A
}

func newGate(name, addr, username, password string) *gate {
	g := &gate{
		name:     name,
		addr:     addr,
		username: username,
		password: password,
		a: accessory.New(accessory.Info{
			Name:         name,
			Manufacturer: "aljammaz labs",
		}, accessory.TypeGarageDoorOpener),
		g: service.NewGarageDoorOpener(),
	}

	// TODO obstruction detected? if target state != current state aften n seconds
	// of activate.
	g.g.TargetDoorState.OnValueRemoteUpdate(g.setTarget)
	g.a.AddS(g.g.S)

	go g.poll()

	return g
}

func (g *gate) setTarget(target int) {
	state, _, code, err := getinfo(g.addr, g.username, g.password)
	if err != nil {
		log.Printf("could not get door state: %v", err)
		return
	}
	if state != g.g.CurrentDoorState.Value() {
		g.g.CurrentDoorState.SetValue(state)
	}

	if state != target {
		activate(g.addr, g.username, g.password, code)
	}
}

func (g *gate) toggle() {
	_, _, code, err := getinfo(g.addr, g.username, g.password)
	if err != nil {
		log.Printf("could not get door state: %v", err)
		return
	}
	activate(g.addr, g.username, g.password, code)
}

func (g *gate) poll() {
	for {
		state, target, _, err := getinfo(g.addr, g.username, g.password)
		if err != nil {
			log.Printf("could not get door state: %v", err)
			time.Sleep(30 * time.Second)
			continue
		}
		if state != g.g.CurrentDoorState.Value() {
			g.g.CurrentDoorState.SetValue(state)
		}
		if target != g.g.TargetDoorState.Value() {
			g.g.TargetDoorState.SetValue(target)
		}
		time.Sleep(10 * time.Second)
	}
}
