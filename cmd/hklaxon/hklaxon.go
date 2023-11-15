// command hklaxon implements a homekit security device, with
// inputs (motion sensors, contact sensor) connected via as i2c.
package main

import (
	"context"
	"flag"
	"log"
	"os"
	"path/filepath"
	"slices"
	"time"

	"github.com/brutella/hap"
	"github.com/brutella/hap/accessory"
	"github.com/brutella/hap/characteristic"
	"github.com/brutella/hap/service"
	"periph.io/x/conn/v3/i2c"
	"periph.io/x/conn/v3/i2c/i2creg"
	"periph.io/x/host/v3"
)

const (
	inputboard = 0 // the index of the sequent cards in the stack
	relayboard = 1
)

const (
	alarmStay = iota
	alarmAway
	alarmNight
	alarmDisarm
	alarmTriggered
)

var (
	inputs = []sensor{
		newDoor("1"), newDoor("2"), newDoor("3"), newDoor("4"),
		newDoor("5"), newMotion("1"), newMotion("2"), newMotion("3"),
		newMotion("4"), newMotion("5"), newMotion("6"), newMotion("7"),
		newMotion("8"), newMotion("9"), newMotion("10"), newMotion("11"),
		newMotion("12"), newMotion("13"), newMotion("14"), newMotion("15"),
		nil, nil, nil, nil,
		nil, nil, nil, nil,
		nil, nil, nil, nil,
	}

	disabledInputs = []int{5, 12, 14}

	alarmState = alarmDisarm

	acc = accessory.NewSecuritySystem(accessory.Info{Name: "sensors", Manufacturer: "aljammaz labs"})
)

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
	sensors.inputboard = &i2c.Dev{Addr: deviceAddress + (0x07 ^ inputboard), Bus: b}
	sensors.relayboard = &i2c.Dev{Addr: deviceAddress + (0x07 ^ relayboard), Bus: b}

	for i := range inputs {
		if inputs[i] == nil {
			continue
		}
		acc.Ss = append(acc.Ss, inputs[i].service())
	}

	for _, idx := range disabledInputs {
		inputs[idx].update(true)
	}

	acc.SecuritySystem.SecuritySystemCurrentState.SetValue(alarmState)
	acc.SecuritySystem.SecuritySystemTargetState.OnValueRemoteUpdate(updateAlarmState)

	server, err := hap.NewServer(hap.NewFsStore(*statedir), acc.A)
	if err != nil {
		log.Fatalf("could not make hap server: %v", err)
	}

	go pollSensors()
	server.Pin = *pin
	log.Fatal(server.ListenAndServe(context.Background()))
}

func updateAlarmState(state int) {
	acc.SecuritySystem.SecuritySystemCurrentState.SetValue(state)
	alarmState = state
}

func pollSensors() {
	var prev uint32
	for {
		time.Sleep(50 * time.Millisecond)
		state := readState()
		if state == prev {
			continue
		}
		for i := range inputs {
			if inputs[i] == nil {
				continue
			}
			// skip disconnected ones.
			if slices.Contains(disabledInputs, i) {
				continue
			}

			val := (state & (1 << (31 - i))) == 0
			pval := (prev & (1 << (31 - i))) == 0
			if val != pval {
				inputs[i].update(val)
				log.Printf("%d: %v", i, val)
			}
		}
		prev = state
	}
}

type sensor interface {
	update(closed bool)
	service() *service.S
}

type door struct {
	// name is this door's name.
	name string
	// dd is the hap package's service object.
	s *service.ContactSensor
}

func (d *door) service() *service.S { return d.s.S }

// update value from sensors
func (d *door) update(closed bool) {
	if closed {
		d.s.ContactSensorState.SetValue(0)
	} else {
		d.s.ContactSensorState.SetValue(1)
		switch alarmState {
		case alarmStay, alarmAway, alarmNight:
			updateAlarmState(alarmTriggered)
		}
	}
}

func newDoor(name string) *door {
	d := &door{name, service.NewContactSensor()}
	n := characteristic.NewName()
	n.SetValue(name)
	d.s.AddC(n.C)

	d.s.ContactSensorState.SetValue(0)

	return d
}

type motion struct {
	// name is this motion sensor's name.
	name string
	// dd is the hap package's service object.
	s *service.MotionSensor
}

func (m *motion) service() *service.S { return m.s.S }

// update value from sensors
func (m *motion) update(signal bool) {
	m.s.MotionDetected.SetValue(!signal)
	if !signal {
		switch alarmState {
		case alarmStay, alarmAway, alarmNight:
			updateAlarmState(alarmTriggered)
		}
	}
}

func newMotion(name string) *motion {
	d := &motion{name, service.NewMotionSensor()}
	n := characteristic.NewName()
	n.SetValue(name)
	d.s.AddC(n.C)

	d.s.MotionDetected.SetValue(false)

	return d
}
