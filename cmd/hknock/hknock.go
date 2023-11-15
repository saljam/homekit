// command hknock implements a homekit doorbell and buzzer.
package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"

	"github.com/brutella/hap"
	"github.com/brutella/hap/accessory"
	"github.com/brutella/hap/rtp"
	"github.com/brutella/hap/service"
	"github.com/brutella/hap/tlv8"
	"periph.io/x/conn/v3/i2c"
	"periph.io/x/conn/v3/i2c/i2creg"
	"periph.io/x/host/v3"
)

const (
	card           = 1                   // index of the Sequent card in the stack.
	doorEastRelay  = 0                   // index of the relay used for the first door.
	doorEastRTSP   = "rtsp://192.0.2.1/" // url for the first door's video feed.
	doorSouthRelay = 1                   // index of the relay used for the second door.
	doorSouthRTSP  = "rtsp://192.0.2.2/" // url for the first door's video feed.
)

func buzz(r int) {
	setRelay(r, true)
	go func() {
		time.Sleep(1 * time.Second)
		setRelay(r, false)
	}()
}

var doors = []*door{
	newDoor("east", doorEastRelay, doorEastRTSP),
	newDoor("south", doorSouthRelay, doorSouthRTSP),
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
	server.Addr = ":8000"
	log.Fatal(server.ListenAndServe(context.Background()))
}

func handleResource(w http.ResponseWriter, r *http.Request) {
	// skip server.IsAuthorized(r)
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
	case "image":
		door.Lock()
		buf := door.snapshot
		ts := door.snapshotTimestamp
		door.Unlock()
		if time.Since(ts) > 30*time.Second {
			newbuf, err := door.updateSnapshot()
			if err != nil {
				buf = newbuf
			}
		}
		if buf == nil {
			http.Error(w, "not found", http.StatusNotFound)
			log.Printf("no snapshot for %v", msg.AID)
			return
		}
		log.Printf("snapshot for: %v", door.name)
		chunked := hap.NewChunkedWriter(w, 2048)
		_, err = chunked.Write(buf)
		if err != nil {
			log.Printf("could write image: %v", err)
		}
	case "open":
		door.updateLock(0)
		fmt.Fprintf(w, "yes\n")
	case "ring":
		log.Printf("ringing bell: %v", door.name)
		//0 ”Single Press”
		//1 ”Double Press”
		//2 ”Long Press”
		door.doorbell.ProgrammableSwitchEvent.SetValue(0)
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
	// upstreamURL is the RSTP upstreamURL URL.
	upstreamURL string
	// The hap package's service object.
	doorbell   *service.Doorbell
	mgmt       *service.CameraRTPStreamManagement
	speaker    *service.Speaker
	microphone *service.Microphone
	lock       *service.LockMechanism

	a *accessory.A

	sync.Mutex
	snapshot          []byte
	snapshotTimestamp time.Time
	streams           map[string]*stream
}

type stream struct {
	setup  rtp.SetupEndpoints
	ssrc   int
	ctx    context.Context
	cancel func()
}

func newDoor(name string, relay int, streamURL string) *door {
	d := &door{
		name:        name,
		relay:       relay,
		upstreamURL: streamURL,
		doorbell:    service.NewDoorbell(),
		mgmt:        service.NewCameraRTPStreamManagement(),
		speaker:     service.NewSpeaker(),
		microphone:  service.NewMicrophone(),
		lock:        service.NewLockMechanism(),
		streams:     make(map[string]*stream),

		a: accessory.New(accessory.Info{
			Name:         name,
			Manufacturer: "aljammaz labs",
		}, accessory.TypeVideoDoorbell),
	}

	// Doorbell
	d.a.AddS(d.doorbell.S)

	// Video
	d.mgmt.StreamingStatus.SetValue(mustTVL8Marshal(rtp.StreamingStatus{Status: rtp.StreamingStatusAvailable}))
	d.mgmt.SupportedRTPConfiguration.SetValue(mustTVL8Marshal(rtp.NewConfiguration(rtp.CryptoSuite_AES_CM_128_HMAC_SHA1_80)))
	d.mgmt.SupportedVideoStreamConfiguration.SetValue(mustTVL8Marshal(rtp.DefaultVideoStreamConfiguration()))
	d.mgmt.SupportedAudioStreamConfiguration.SetValue(mustTVL8Marshal(rtp.DefaultAudioStreamConfiguration()))
	d.mgmt.SelectedRTPStreamConfiguration.OnValueRemoteUpdate(d.selectRTPStreamConfig)
	d.mgmt.SetupEndpoints.OnValueUpdate(d.setupEndpoints)
	d.a.AddS(d.mgmt.S)

	d.speaker.Mute.OnValueRemoteUpdate(func(v bool) {
		log.Printf("speaker mute: %v", v)
	})
	d.microphone.Mute.OnValueRemoteUpdate(func(v bool) {
		log.Printf("microphone mute: %v", v)
	})

	// Lock
	// Initialise to closed.
	d.lock.LockCurrentState.SetValue(1)
	d.lock.LockTargetState.SetValue(1)
	d.lock.LockTargetState.OnValueRemoteUpdate(d.updateLock)
	d.a.AddS(d.lock.S)

	return d
}

func (d *door) updateSnapshot() ([]byte, error) {
	buf := &bytes.Buffer{}
	cmd := exec.Command("ffmpeg",
		"-rtsp_transport", "tcp",
		"-i", d.upstreamURL,
		"-f", "image2",
		"-frames:v", "1",
		"-",
	)
	cmd.Stdout = buf
	err := cmd.Run()

	d.Lock()
	defer d.Unlock()
	d.snapshot = buf.Bytes()
	d.snapshotTimestamp = time.Now()

	return buf.Bytes(), err
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

func (d *door) selectRTPStreamConfig(buf []byte) {
	d.Lock()
	defer d.Unlock()
	var cfg rtp.StreamConfiguration
	err := tlv8.Unmarshal(buf, &cfg)
	if err != nil {
		log.Printf("could not unmarshal tlv8: %s", err)
		return
	}

	s := d.streams[string(cfg.Command.Identifier)]

	b64 := base64.RawStdEncoding.EncodeToString

	switch cfg.Command.Type {
	case rtp.SessionControlCommandTypeStart:
		log.Printf("start %s", b64(cfg.Command.Identifier))
		ctx, cancel := context.WithCancel(s.ctx)
		s.cancel = cancel
		s.startStream(ctx, cfg, d.upstreamURL)
	case rtp.SessionControlCommandTypeSuspend:
		log.Printf("suspend %s", b64(cfg.Command.Identifier))
	case rtp.SessionControlCommandTypeResume:
		log.Printf("resume %s", b64(cfg.Command.Identifier))
	case rtp.SessionControlCommandTypeReconfigure:
		log.Printf("reconfigure %s", b64(cfg.Command.Identifier))
	case rtp.SessionControlCommandTypeEnd:
		log.Printf("stop %s", b64(cfg.Command.Identifier))
		if s.cancel != nil {
			s.cancel()
		}
		delete(d.streams, string(cfg.Command.Identifier))
		d.mgmt.SetupEndpoints.Bytes.SetValue(mustTVL8Marshal(rtp.StreamingStatus{Status: rtp.StreamingStatusAvailable}))
	default:
		log.Printf("unknown command: %d", cfg.Command.Type)
	}
}

func (d *door) setupEndpoints(new, old []byte, r *http.Request) {
	if r == nil {
		// why does this ever get called with a nil request?
		return
	}

	var req rtp.SetupEndpoints
	err := tlv8.Unmarshal(new, &req)
	if err != nil {
		log.Printf("could not unmarshal tlv8: %v", err)
		return
	}

	addr, _ := r.Context().Value(http.LocalAddrContextKey).(net.Addr)
	ipaddr, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		log.Printf("could parse local address (%v): %v", addr, err)
		return
	}

	resp := rtp.SetupEndpointsResponse{
		SessionId: req.SessionId,
		Status:    rtp.SessionStatusSuccess,
		AccessoryAddr: rtp.Addr{
			IPVersion:    req.ControllerAddr.IPVersion,
			IPAddr:       ipaddr,
			VideoRtpPort: req.ControllerAddr.VideoRtpPort,
			AudioRtpPort: req.ControllerAddr.AudioRtpPort,
		},
		Video:     req.Video,
		Audio:     req.Audio,
		SsrcVideo: rand.Int31(),
		SsrcAudio: rand.Int31(),
	}

	d.Lock()
	defer d.Unlock()
	d.streams[string(req.SessionId)] = &stream{
		setup: req,
		ssrc:  int(resp.SsrcVideo),
		ctx:   context.Background(),
	}

	d.mgmt.SetupEndpoints.SetValue(mustTVL8Marshal(resp))
}

func (s *stream) startStream(ctx context.Context, cfg rtp.StreamConfiguration, url string) {
	mtu := 1228
	if s.setup.ControllerAddr.IPVersion == rtp.IPAddrVersionv4 {
		mtu = 1378
	}

	cmd := exec.CommandContext(ctx, "ffmpeg",
		"-i", url,
		"-c", "copy",
		"-an",
		"-f", "rtp",
		"-payload_type", fmt.Sprintf("%d", cfg.Video.RTP.PayloadType),
		"-ssrc", fmt.Sprintf("%d", s.ssrc),
		"-srtp_out_suite", "AES_CM_128_HMAC_SHA1_80",
		"-srtp_out_params", fmt.Sprintf("%s", s.setup.Video.SrtpKey()),
		fmt.Sprintf("srtp://%s:%d?rtcpport=%d&pkt_size=%d&timeout=60", s.setup.ControllerAddr.IPAddr, s.setup.ControllerAddr.VideoRtpPort, s.setup.ControllerAddr.VideoRtpPort, mtu),
	)
	cmd.Stdout = os.Stdout
	err := cmd.Start()
	if err != nil {
		log.Printf("could not start ffmpeg process: %v", err)
		return
	}
	go cmd.Wait()
}

func mustTVL8Marshal(v any) []byte {
	buf, err := tlv8.Marshal(v)
	if err != nil {
		panic(err)
	}
	return buf
}
