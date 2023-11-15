package main

import (
	"encoding/binary"
	"log"
	"sync"

	"periph.io/x/conn/v3/i2c"
)

const (
	// i2c registers for Sequent 16-input and Sequent 4-relay/4-input boards.
	registerIn     = 0x00
	registerOut    = 0x01
	registerPolinv = 0x02
	registerCfg    = 0x03 // Example code writes 0x0f here if it's not 0x0f already
	deviceAddress  = 0x20
)

var sensors struct {
	inputboard *i2c.Dev
	relayboard *i2c.Dev
	sync.Mutex
}

func readOpto(i int) bool {
	if i < 0 || 15 < i {
		panic("i is out of range")
	}
	s := readState()
	return (s & (1 << (15 - i))) == 0
}

func readState() uint32 {
	sensors.Lock()
	defer sensors.Unlock()
	buf := make([]byte, 4)

	// input board
	if err := sensors.inputboard.Tx([]byte{registerIn}, buf[:2]); err != nil {
		log.Printf("could not read value: %v", err)
	}

	// relay board
	if err := sensors.relayboard.Tx([]byte{registerCfg}, buf[2:3]); err != nil {
		log.Printf("could not read cfg value: %v", err)
	}
	if buf[2] != 0x0f {
		if err := sensors.relayboard.Tx([]byte{registerCfg, 0x0f}, nil); err != nil {
			log.Printf("could not write value: %v", err)
		}
	}
	if err := sensors.relayboard.Tx([]byte{registerIn}, buf[2:3]); err != nil {
		log.Printf("could not read value: %v", err)
	}
	buf[2] = (buf[2] & 0xf) << 4

	// be so the doors end up at the start.
	return binary.BigEndian.Uint32(buf)
}
