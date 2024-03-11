package main

import (
	"log"
	"sync"

	"periph.io/x/conn/v3/i2c"
)

const (
	// Sequent 4-relay/4-input registers.
	registerIn     = 0x00
	registerOut    = 0x01
	registerPolinv = 0x02
	registerCfg    = 0x03 // Example code writes 0x0f here if it's not 0x0f already.
	deviceAddress  = 0x20
)

var relay struct {
	*i2c.Dev
	sync.Mutex
}

func readRelay(i int) bool {
	if i < 0 || 3 < i {
		panic("i is out of range")
	}
	s := readState()
	return (s & (1 << (7 - i))) != 0
}

func readOpto(i int) bool {
	if i < 0 || 3 < i {
		panic("i is out of range")
	}
	s := readState()
	return (s & (1 << (3 - i))) == 0
}

func readState() byte {
	if relay.Dev == nil {
		log.Println("get: no relay configured")
		return 0
	}
	relay.Lock()
	defer relay.Unlock()
	buf := make([]byte, 1)
	if err := relay.Tx([]byte{registerCfg}, buf); err != nil {
		log.Printf("could not read cfg value: %v", err)
	}
	if buf[0] != 0x0f {
		if err := relay.Tx([]byte{registerCfg, 0x0f}, nil); err != nil {
			log.Printf("could not write value: %v", err)
		}
	}
	if err := relay.Tx([]byte{registerIn}, buf); err != nil {
		log.Printf("could not read value: %v", err)
	}
	return buf[0]
}

func setRelay(i int, v bool) {
	if relay.Dev == nil {
		log.Println("set: no relay configured")
		return
	}
	if i < 0 || 3 < i {
		panic("i is out of range")
	}
	s := readState() & 0xf0 // 0 out the optos
	if v {
		s |= (1 << (7 - i))
	} else {
		s &= ^(1 << (7 - i))
	}
	relay.Lock()
	defer relay.Unlock()
	if err := relay.Tx([]byte{registerOut, s}, nil); err != nil {
		log.Printf("could not write value: %v", err)
	}
}
