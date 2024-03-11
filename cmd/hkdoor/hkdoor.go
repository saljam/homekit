// command hkgate serves a homekit accessory that controls a door buzzer using
// relays on a sequent i2c card.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
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
)

func buzz(r int) {
	setRelay(r, true)
	go func() {
		time.Sleep(1 * time.Second)
		setRelay(r, false)
	}()
}

var doors = []*door{
	newDoor("east", doorEastRelay),
	newDoor("south", doorSouthRelay),
}

func main() {
	log.SetFlags(0)
	log.SetPrefix("")
	pin := flag.String("pin", "", "homekit pin")
	addr := flag.String("addr", ":8000", "listen address")
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

	bridge := accessory.NewBridge(accessory.Info{Name: "doors", Manufacturer: "aljammaz labs"}).A
	bridge.Id = 1
	for i := range doors {
		doors[i].a.Id = uint64(i + 2)
	}

	server, err := hap.NewServer(
		hap.NewFsStore(*statedir),
		bridge, doors[0].a, doors[1].a,
	)
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

	door := doors[index]
	switch msg.Type {
	case "open":
		door.updateLock(0)
		fmt.Fprintf(w, "yes\n")
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
	// The hap package's service object.
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
		}, accessory.TypeVideoDoorbell),
		lock: service.NewLockMechanism(),
	}

	// Lock
	// Initialise to closed.
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
