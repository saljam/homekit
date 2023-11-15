// command hknx exports knx devices as homekit accessories.
//
// only lights, fans, and window coverings are supported, and it assumes a rigid
// structure for the knx group addresses.
//
// reads group addresses from a tsv file, columns are address, name, description. only
// the write addresses should be there. the status addresses are assumed to be +1.
//
// from ets: export group addresses, select the first option "3/1". remove quotes, filter
// out status objects, filter out main and middle groups we don't use, and select the
// columns we need:
//
//	<groupaddrs.csv sed 's/"//g' | awk 'BEGIN { FS = "\t"; OFS = "\t" } (/SW/ || /POS/) && !match($4, /^0|\/0\//) {print $4, $3 $7}' > devices.tsv
package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/brutella/hap"
	"github.com/brutella/hap/accessory"
	"github.com/vapourismo/knx-go/knx"
	"github.com/vapourismo/knx-go/knx/cemi"
)

var (
	knxtunneladdr string
	knxclient     *knx.GroupTunnel
	knxclientMu   sync.Mutex

	lights  = map[cemi.GroupAddr]*light{}
	windows = map[cemi.GroupAddr]*window{}
	fans    = map[cemi.GroupAddr]*fan{}
)

func main() {
	log.SetFlags(0)
	log.SetPrefix("")
	flag.StringVar(&knxtunneladdr, "knxtunnel", "", "address of knx tunnel")
	pin := flag.String("pin", "", "homekit pin")
	statedir := flag.String("state", filepath.Join(os.Getenv("HOME"), "hk", filepath.Base(os.Args[0])), "state directory")
	groupaddrfile := flag.String("groupaddrs", "", "path to group addresses tsv file")
	flag.Parse()

	if *groupaddrfile == "" {
		log.Fatalf("must provide group addresses file")
	}
	f, err := os.Open(*groupaddrfile)
	if err != nil {
		log.Fatalf("could not read group addresses file: %v", err)
	}
	parse(f)

	as := []*accessory.A{}
	for _, a := range lights {
		as = append(as, a.a.A)
	}
	for _, a := range windows {
		as = append(as, a.a.A)
	}
	for _, a := range fans {
		as = append(as, a.a.A)
	}

	slices.SortFunc(as, func(a, b *accessory.A) int {
		return int(a.Id) - int(b.Id) // knx group addresses are 16 bit.
	})

	n := 1
	for len(as) > 0 {
		l := len(as)
		if l > 140 {
			l = 140
		}
		shard := as[:l]
		as = as[l:]

		bridge := accessory.NewBridge(accessory.Info{Name: fmt.Sprintf("knx-bridge-%d", n), Manufacturer: "aljammaz labs"}).A
		bridge.Id = 1
		server, err := hap.NewServer(hap.NewFsStore(filepath.Join(*statedir, strconv.Itoa(n))), bridge, shard...)
		if err != nil {
			log.Fatalf("could not make hap server: %v", err)
		}
		server.Pin = *pin
		log.Printf("%d devices on knx-bridge-%d", l, n)
		go server.ListenAndServe(context.Background())
		n++
	}

	for {
		// periodically attempt to read all state from knx, in case we
		// missed any events because the tunnel was down.
		log.Printf("starting read requests")
		err := knxreadall()
		if err != nil {
			log.Printf("could not send read requests: %v", err)
		} else {
			log.Printf("finished read requests")
		}
		time.Sleep(6 * time.Hour)
	}
}

type light struct {
	name   string
	swAddr cemi.GroupAddr

	a *accessory.Lightbulb
}

func (ac *light) update(on bool) error {
	var v byte = 0
	if on {
		v = 1
	}
	return knxsend(cemi.GroupAddr(ac.swAddr), []byte{v})
}

func newLight(name string, addr cemi.GroupAddr) *light {
	ac := &light{
		name:   name,
		swAddr: addr,
		a:      accessory.NewLightbulb(accessory.Info{Name: name, Manufacturer: "aljammaz labs"}),
	}
	ac.a.Id = uint64(addr)
	ac.a.Lightbulb.On.OnSetRemoteValue(ac.update)
	return ac
}

type window struct {
	name    string
	posAddr cemi.GroupAddr

	a *accessory.WindowCovering
}

func (ac *window) update(v int) error {
	return knxsend(cemi.GroupAddr(ac.posAddr), []byte{0, byte(((100 - v) * 255) / 100)})
}

func newWindow(name string, addr cemi.GroupAddr) *window {
	ac := &window{
		name:    name,
		posAddr: addr,
		a:       accessory.NewWindowCovering(accessory.Info{Name: name, Manufacturer: "aljammaz labs"}),
	}
	ac.a.Id = uint64(addr)
	ac.a.WindowCovering.TargetPosition.OnSetRemoteValue(ac.update)
	return ac
}

type fan struct {
	name   string
	swAddr cemi.GroupAddr

	a *accessory.Fan
}

func (ac *fan) update(on bool) error {
	var v byte = 0
	if on {
		v = 1
	}
	return knxsend(cemi.GroupAddr(ac.swAddr), []byte{v})
}

func newFan(name string, addr cemi.GroupAddr) *fan {
	ac := &fan{
		name:   name,
		swAddr: addr,
		a:      accessory.NewFan(accessory.Info{Name: name, Manufacturer: "aljammaz labs"}),
	}
	ac.a.Id = uint64(addr)
	ac.a.Fan.On.OnSetRemoteValue(ac.update)
	return ac
}

func reconnect() error {
	log.Printf("reconnecting knx tunnel")

	c, err := knx.NewGroupTunnel(knxtunneladdr, knx.TunnelConfig{
		ResendInterval:    500 * time.Millisecond,
		HeartbeatInterval: 10 * time.Second,
		ResponseTimeout:   2 * time.Second,
		SendLocalAddress:  false,
		UseTCP:            true,
	})
	if err != nil {
		log.Printf("could not start knx tunnel: %v", err)
		return err
	}
	knxclient = &c
	go knxwatch(knxclient)
	log.Printf("finished knx tunnel")
	return nil
}

func disconnect() {
	if knxclient == nil {
		return
	}

	knxclient.Close()
	knxclient = nil
}

func knxsend(grp cemi.GroupAddr, v []byte) error {
	knxclientMu.Lock()
	defer knxclientMu.Unlock()
	if knxclient == nil {
		err := reconnect()
		if err != nil {
			return err
		}
	}
	err := knxclient.Send(knx.GroupEvent{Command: knx.GroupWrite, Destination: grp, Data: v})
	if err != nil {
		log.Printf("could not send knx value: %v", err)
		disconnect()
	}
	return err
}

func knxwatch(tunnel *knx.GroupTunnel) {
	for msg := range tunnel.Inbound() {
		if l, ok := lights[msg.Destination]; ok && len(msg.Data) == 1 {
			l.a.Lightbulb.On.SetValue(msg.Data[0] != 0)
			continue
		}
		if l, ok := fans[msg.Destination]; ok && len(msg.Data) == 1 {
			l.a.Fan.On.SetValue(msg.Data[0] != 0)
			continue
		}
		if l, ok := windows[msg.Destination]; ok && len(msg.Data) == 2 {
			l.a.WindowCovering.CurrentPosition.SetValue((int(255-msg.Data[1]) * 100) / 255)
			l.a.WindowCovering.TargetPosition.SetValue((int(255-msg.Data[1]) * 100) / 255)
			l.a.WindowCovering.PositionState.SetValue(2) // stopped
			continue
		}
	}
	log.Println("finishing knx watch goroutine")
}

func knxreadall() error {
	knxclientMu.Lock()
	defer knxclientMu.Unlock()
	if knxclient == nil {
		err := reconnect()
		if err != nil {
			return err
		}
	}

	for addr := range lights {
		err := knxclient.Send(knx.GroupEvent{
			Command:     knx.GroupRead,
			Destination: addr,
		})
		if err != nil {
			return err
		}
		time.Sleep(100 * time.Millisecond)
	}
	for addr := range windows {
		err := knxclient.Send(knx.GroupEvent{
			Command:     knx.GroupRead,
			Destination: addr,
		})
		if err != nil {
			return err
		}
		time.Sleep(100 * time.Millisecond)
	}
	for addr := range fans {
		err := knxclient.Send(knx.GroupEvent{
			Command:     knx.GroupRead,
			Destination: addr,
		})
		if err != nil {
			return err
		}
		time.Sleep(100 * time.Millisecond)
	}
	return nil
}

func parse(r io.Reader) {
	n := 0
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		parts := strings.Split(scanner.Text(), "\t")
		if len(parts) != 3 {
			log.Fatalf("unexpected number of columns in line %v", n+1)
		}
		addr, err := cemi.NewGroupAddrString(parts[0])
		if err != nil {
			log.Fatalf("invalid address (%v) in line %v", parts[0], n+1)
		}
		// match middle group.
		switch (addr >> 8) & 0x7 {
		case 1:
			// light
			lights[addr+1] = newLight(parts[2], addr)
		case 2:
			// shutter
			windows[addr+1] = newWindow(parts[2], addr)
		case 3:
			// curtain
			windows[addr+1] = newWindow(parts[2], addr)
		case 4:
			// fan
			fans[addr+1] = newFan(parts[2], addr)
		default:
			log.Fatalf("unknown middle group (%v) in line %v", parts[1], n+1)
		}
		n++
	}
	if err := scanner.Err(); err != nil {
		log.Fatalf("error reading devices: %v", err)
	}
	log.Printf("read %v devices. %v lights, %v window coverings, %v fans", n, len(lights), len(windows), len(fans))
}
