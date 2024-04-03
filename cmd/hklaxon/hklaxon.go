// command hklaxon implements a homekit security device, using motion and
// contact sensors connected to the inputs on a sequent i2c card.
package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
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
	inputs     = make([]sensor, 32)
	alarmState = alarmDisarm
	acc        = accessory.NewSecuritySystem(accessory.Info{Name: "sensors", Manufacturer: "aljammaz labs"})
	doorcmd    = ""
)

func main() {
	log.SetFlags(0)
	log.SetPrefix("")
	doors := flag.Uint("doors", 0x0, "32 bit mask of the door sensor inputs")
	motion := flag.Uint("motion", 0x0, "32 bit mask of the motion sensor inputs")
	pin := flag.String("pin", "", "homekit pin")
	flag.StringVar(&doorcmd, "doorcmd", "", "command to run in a shell when a door is opened or closed")
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

	for i := 0; i < 32; i++ {
		if (*doors>>i)&1 == 1 {
			inputs[i] = newDoor(strconv.Itoa(i))
			acc.Ss = append(acc.Ss, inputs[i].service())
		}
		if (*motion>>i)&1 == 1 {
			inputs[i] = newMotion(strconv.Itoa(i))
			acc.Ss = append(acc.Ss, inputs[i].service())
		}
		if (*doors>>i)&1 == 1 && (*motion>>i)&1 == 1 {
			log.Fatalf("input %d is both a door and a motion sensor. check your bit masks!", i)
		}
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
	if doorcmd == "" {
		return
	}
	go func() {
		if closed {
			err := exec.Command(doorcmd, d.name, "closed").Run()
			if err != nil {
				log.Printf("could not run doorcmd: %v", err)
			}
		} else {
			err := exec.Command(doorcmd, d.name, "opened").Run()
			if err != nil {
				log.Printf("could not run doorcmd: %v", err)
			}
		}
	}()
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
