// command hknock-sensor is similar to hknock but uses an i2c input for the doorbell
// instead of an http endpoint.
package main

import (
	"context"
	"flag"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/brutella/hap"
	"github.com/brutella/hap/accessory"
	"github.com/brutella/hap/service"
	"periph.io/x/conn/v3/i2c"
	"periph.io/x/conn/v3/i2c/i2creg"
	"periph.io/x/host/v3"
)

const (
	// Sequent 4-relay/4-input registers.
	registerIn     = 0x00
	registerOut    = 0x01
	registerPolinv = 0x02
	registerCfg    = 0x03 // Example code writes 0x0f here if it's not 0x0f already
	deviceAddress  = 0x20
)

const (
	card      = 0 // The index of the Sequent card in the stack
	gateRelay = 3 // The index of the relay used for the gate
	bellOpto  = 3 // The index of the optocoupler used for the intercom
)

type gate struct {
	accessory *accessory.A
	opener    *service.GarageDoorOpener
	bell      *service.Doorbell

	deviceMu sync.Mutex
	device   *i2c.Dev
}

func newGate(d *i2c.Dev) *gate {
	a := accessory.NewGarageDoorOpener(accessory.Info{
		Name:         "gate",
		SerialNumber: "4911409",
		Manufacturer: "aljammaz labs",
		Model:        "mark 2",
		Firmware:     "0.0.1",
	})

	g := &gate{
		accessory: a.A,
		opener:    a.GarageDoorOpener,
		device:    d,
	}

	a.GarageDoorOpener.TargetDoorState.OnValueRemoteUpdate(func(v int) {
		switch v {
		case 0:
			log.Printf("openning gate")
			g.openGate()
			a.GarageDoorOpener.CurrentDoorState.SetValue(v)
			go func() {
				time.Sleep(5 * time.Second)
				a.GarageDoorOpener.TargetDoorState.SetValue(1)
				a.GarageDoorOpener.CurrentDoorState.SetValue(1)
			}()
		case 1:
			log.Printf("closing gate")
			g.closeGate()
			a.GarageDoorOpener.CurrentDoorState.SetValue(v)
		default:
			log.Printf("unknown state requested: %v", v)
			return
		}
	})

	// Initialise to closed.
	a.GarageDoorOpener.TargetDoorState.SetValue(1)
	a.GarageDoorOpener.CurrentDoorState.SetValue(1)

	g.bell = service.NewDoorbell()
	a.AddS(g.bell.S)

	go g.pollBell()

	return g
}

func (g *gate) openGate() {
	g.setRelay(gateRelay, true)
	go func() {
		time.Sleep(500 * time.Millisecond)
		g.setRelay(gateRelay, false)
	}()
}

func (g *gate) closeGate() {
	g.setRelay(gateRelay, false)
}

func (g *gate) pollBell() {
	for {
		time.Sleep(50 * time.Millisecond)
		if g.readOpto(bellOpto) {
			log.Printf("ringing bell")
			g.bell.ProgrammableSwitchEvent.SetValue(0)
			time.Sleep(1 * time.Second)
		}
	}
}

func (g *gate) readState() byte {
	g.deviceMu.Lock()
	defer g.deviceMu.Unlock()
	buf := make([]byte, 1)
	if err := g.device.Tx([]byte{registerCfg}, buf); err != nil {
		log.Printf("could not read cfg value: %v", err)
	}
	if buf[0] != 0x0f {
		if err := g.device.Tx([]byte{registerCfg, 0x0f}, nil); err != nil {
			log.Printf("could not write value: %v", err)
		}
	}
	if err := g.device.Tx([]byte{registerIn}, buf); err != nil {
		log.Printf("could not read value: %v", err)
	}
	return buf[0]
}

func (g *gate) readRelay(i int) bool {
	if i < 0 || 3 < i {
		panic("i is out of range")
	}
	s := g.readState()
	return (s & (1 << (7 - i))) != 0
}

func (g *gate) setRelay(i int, v bool) {
	if i < 0 || 3 < i {
		panic("i is out of range")
	}
	s := g.readState() & 0xf0 // 0 out the optos
	if v {
		s |= (1 << (7 - i))
	} else {
		s &= ^(1 << (7 - i))
	}
	g.deviceMu.Lock()
	defer g.deviceMu.Unlock()
	if err := g.device.Tx([]byte{registerOut, s}, nil); err != nil {
		log.Printf("could not write value: %v", err)
	}
	return
}

func (g *gate) readOpto(i int) bool {
	if i < 0 || 3 < i {
		panic("i is out of range")
	}
	s := g.readState()
	return (s & (1 << (3 - i))) == 0
}

func main() {
	log.SetFlags(0)
	log.SetPrefix("")
	pin := flag.String("pin", "", "homekit pin")
	statedir := flag.String("state", filepath.Join(os.Getenv("HOME"), "hk", filepath.Base(os.Args[0])), "state directory")
	flag.Parse()

	if _, err := host.Init(); err != nil {
		log.Fatalf("could not init i2c: %v", err)
	}
	b, err := i2creg.Open("")
	if err != nil {
		log.Fatalf("could not open i2c device: %v", err)
	}
	gate := newGate(&i2c.Dev{Addr: deviceAddress + (0x07 ^ card), Bus: b})

	server, err := hap.NewServer(hap.NewFsStore(*statedir), gate.accessory)
	if err != nil {
		log.Fatalf("could not make hap server: %v", err)
	}

	server.Pin = *pin
	log.Fatal(server.ListenAndServe(context.TODO()))
}
