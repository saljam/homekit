// command hkam bridges rtsp cameras to homekit.
//
// this uses ffmpeg for snapshots and expects it in $PATH.
package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"github.com/bluenviron/gortsplib/v4"
	"github.com/bluenviron/gortsplib/v4/pkg/base"
	"github.com/bluenviron/gortsplib/v4/pkg/format"
	"github.com/bluenviron/gortsplib/v4/pkg/format/rtph264"
	"github.com/brutella/hap"
	"github.com/brutella/hap/accessory"
	"github.com/brutella/hap/characteristic"
	hkrtp "github.com/brutella/hap/rtp"
	"github.com/brutella/hap/service"
	"github.com/brutella/hap/tlv8"
	"github.com/pion/rtcp"
	"github.com/pion/rtp"
	"github.com/pion/srtp/v3"
)

var (
	server *hap.Server
)

func main() {
	log.SetFlags(0)
	log.SetPrefix("")
	pin := flag.String("pin", "", "homekit pin")
	statedir := flag.String("state", filepath.Join(os.Getenv("HOME"), "hk", filepath.Base(os.Args[0])), "state directory")
	flag.Parse()
	cameraURLs := flag.Args()

	as := []*accessory.A{}
	for i, url := range cameraURLs {
		a := newCamera(fmt.Sprintf("%d", i+1), url)
		a.Id = uint64(i + 2)
		as = append(as, a)
	}

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

	bridge := accessory.NewBridge(accessory.Info{
		Name:         "cams-" + string(id),
		SerialNumber: "something",
		Manufacturer: "aljammaz labs",
	}).A
	bridge.Id = 1

	server, err = hap.NewServer(hap.NewFsStore(*statedir), bridge, as...)
	if err != nil {
		log.Fatalf("could not make hap server: %v", err)
	}
	server.Pin = *pin

	snapshots.bufs = make([][]byte, len(cameraURLs))
	snapshots.timestamps = make([]time.Time, len(cameraURLs))
	snapshots.fetch = make(chan struct{})
	go pollSnapshots(cameraURLs)
	server.ServeMux().HandleFunc("/resource", handleSnapshot)

	log.Fatal(server.ListenAndServe(context.Background()))
}

var snapshots struct {
	sync.Mutex
	bufs       [][]byte
	timestamps []time.Time

	fetch chan struct{}
}

func pollSnapshots(cameraURLs []string) {
	go func() {
		snapshots.fetch <- struct{}{}
		for range time.Tick(5 * time.Minute) {
			snapshots.fetch <- struct{}{}
		}
	}()

	for range snapshots.fetch {
		log.Printf("refreshing snapshots")
		bufs := make([][]byte, len(cameraURLs))
		for i, u := range cameraURLs {
			b, err := fetchSnapshot(u)
			if err != nil {
				log.Printf("could not get snapshot for camera %v: %v", i, err)
				continue
			}
			bufs[i] = b
		}

		snapshots.Lock()
		for i := range bufs {
			if bufs[i] != nil {
				snapshots.bufs[i] = bufs[i]
				snapshots.timestamps[i] = time.Now()
			}
		}
		snapshots.Unlock()
		log.Printf("refreshing snapshots: done")
	}
}

func fetchSnapshot(u string) ([]byte, error) {
	buf := &bytes.Buffer{}
	cmd := exec.Command("ffmpeg",
		"-rtsp_transport", "tcp",
		"-i", u,
		"-f", "image2",
		"-frames:v", "1",
		"-",
	)
	cmd.Stdout = buf
	err := cmd.Run()
	return buf.Bytes(), err
}

func handleSnapshot(w http.ResponseWriter, r *http.Request) {
	if !server.IsAuthorized(r) {
		hap.JsonError(w, hap.JsonStatusInsufficientPrivileges)
		return
	}

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

	if msg.Type != "image" {
		log.Printf("/resource: unexpected type: %v", msg.Type)
		http.Error(w, "unexpected type", http.StatusBadRequest)
		return
	}

	// ID 1 is the bridge
	// IDs 2 onwards are our devices
	index := msg.AID - 2
	if !(0 <= index && index < len(snapshots.bufs)) {
		log.Printf("/resource: unknown accessory id: %v", msg.AID)
		http.Error(w, "unexpected id", http.StatusBadRequest)
		return
	}

	snapshots.Lock()
	buf := snapshots.bufs[index]
	ts := snapshots.timestamps[index]
	snapshots.Unlock()

	if time.Since(ts) > 5*time.Second {
		select {
		case snapshots.fetch <- struct{}{}:
		default:
		}
	}

	if buf == nil {
		http.Error(w, "not found", http.StatusNotFound)
		log.Printf("no snapshot for %v", msg.AID)
		return
	}
	w.Header().Set("Last-Modified", ts.Format(http.TimeFormat))
	chunked := hap.NewChunkedWriter(w, 2048)
	_, err = chunked.Write(buf)
	if err != nil {
		log.Printf("could write image: %v", err)
	}
}

type camera struct {
	// streams is the map of live rtp streams.
	sync.Mutex
	streams map[string]*stream

	// upstreamURL is the upstream rtsp:// video URL.
	upstreamURL string

	// homekit api objects.
	a          *accessory.A
	mgmt       *service.CameraRTPStreamManagement
	mgmtActive *characteristic.Active
	microphone *service.Microphone
}

type stream struct {
	client  *gortsplib.Client
	maxSize int
	vconn   net.Conn
	vssrc   uint32
	vkey    []byte
	ctx     context.Context
	cancel  func()
}

func newCamera(name, upstream string) *accessory.A {
	c := camera{
		upstreamURL: upstream,
		streams:     map[string]*stream{},
		a:           accessory.New(accessory.Info{Name: name, Firmware: "0.0.1", Manufacturer: "aljammaz labs"}, accessory.TypeIPCamera),
		mgmt:        service.NewCameraRTPStreamManagement(),
		mgmtActive:  characteristic.NewActive(),
		microphone:  service.NewMicrophone(),
	}
	c.mgmt.StreamingStatus.SetValue(must(tlv8.Marshal(hkrtp.StreamingStatus{hkrtp.StreamingStatusAvailable})))
	c.mgmt.SupportedRTPConfiguration.SetValue(must(tlv8.Marshal(hkrtp.NewConfiguration(hkrtp.CryptoSuite_AES_CM_128_HMAC_SHA1_80))))
	c.mgmt.SupportedVideoStreamConfiguration.SetValue(must(tlv8.Marshal(hkrtp.DefaultVideoStreamConfiguration())))
	c.mgmt.SupportedAudioStreamConfiguration.SetValue(must(tlv8.Marshal(hkrtp.DefaultAudioStreamConfiguration())))
	c.mgmt.SelectedRTPStreamConfiguration.OnValueRemoteUpdate(c.selectStream)
	c.mgmt.SetupEndpoints.OnValueRemoteUpdate(c.setup)
	c.a.AddS(c.mgmt.S)

	// HomeKit Secure Video things:
	/*
		// TODO RTPStreamManagement Active characteristic
		//c.mgmt.AddC(c.mgmtActive.C)

		// TODO Microphone service
		c.a.AddS(c.microphone.S)

		// TODO MotionSensor service
		motion := service.NewMotionSensor()
		c.a.AddS(motion.S)

		// TOOD CameraOperatingMode service
		opmode := service.New("21A")

		snapshotActive := characteristic.NewBool("223")
		snapshotActive.Permissions = []string{characteristic.PermissionRead, characteristic.PermissionWrite, characteristic.PermissionEvents, characteristic.PermissionTimedWrite}
		snapshotActive.SetValue(true)
		opmode.AddC(snapshotActive.C)

		cameraActive := characteristic.NewBool("21B")
		cameraActive.Permissions = []string{characteristic.PermissionRead, characteristic.PermissionWrite, characteristic.PermissionEvents, characteristic.PermissionTimedWrite}
		cameraActive.SetValue(true)
		opmode.AddC(cameraActive.C)

		periodicSnapshotsActive := characteristic.NewBool("225")
		periodicSnapshotsActive.Permissions = []string{characteristic.PermissionRead, characteristic.PermissionWrite, characteristic.PermissionEvents, characteristic.PermissionTimedWrite}
		periodicSnapshotsActive.SetValue(true)
		opmode.AddC(periodicSnapshotsActive.C)

		c.a.AddS(opmode)
		// TODO CameraEventRecordingManagement service
		recmgmt := service.New("204")

		supportedCameraRecConf := characteristic.NewBytes("205")
		type MediaContainerParam struct {
			FragmentLength uint32 `tlv8:"1"`
		}
		type MediaContainerConf struct {
			MediaContainerType   byte                  `tlv8:"1"`
			MediaContainerParams []MediaContainerParam `tlv8:"-"`
		}
		type CameraRecConf struct {
			Prebuffer           uint32               `tlv8:"1"`
			EventTriggerOptions uint64               `tlv8:"2"`
			MediaContainerConfs []MediaContainerConf `tlv8:"-"`
		}
		supportedCameraRecConf.SetValue(must(tlv8.Marshal(CameraRecConf{
			Prebuffer:           4000,
			EventTriggerOptions: 0x01, // & 0x02
			MediaContainerConfs: []MediaContainerConf{{
				MediaContainerType: 0, // mp4
				MediaContainerParams: []MediaContainerParam{{
					FragmentLength: 4000,
				}},
			}},
		})))
		supportedCameraRecConf.SetValue(nil)
		recmgmt.AddC(supportedCameraRecConf.C)

		supportedVideoRecConf := characteristic.NewBytes("206")
		//supportedVideoRecConf.SetValue(must(tlv8.Marshal(rtp.NewH264VideoCodecConfiguration())))
		recmgmt.AddC(supportedVideoRecConf.C)

		supportedAudioRecConf := characteristic.NewBytes("207")
		//supportedAudioRecConf.SetValue(must(tlv8.Marshal(rtp.NewAacEldAudioCodecConfiguration())))
		recmgmt.AddC(supportedAudioRecConf.C)

		selectedVideoRecConf := characteristic.NewBytes("209")
		recmgmt.AddC(selectedVideoRecConf.C)

		recAudioActive := characteristic.NewInt("226")
		recAudioActive.SetValue(1)
		recmgmt.AddC(recAudioActive.C)

		c.a.AddS(recmgmt)
		// TODO DataStreamManagement service?
	*/

	return c.a
}

func (c *camera) setup(buf []byte) {
	var req hkrtp.SetupEndpoints
	err := tlv8.Unmarshal(buf, &req)
	if err != nil {
		log.Printf("could not unmarshal tlv8: %v", err)
		return
	}

	log.Printf("setup endpoints %v", b64(req.SessionId))

	dst := fmt.Sprintf("%v:%v", req.ControllerAddr.IPAddr, req.ControllerAddr.VideoRtpPort)

	vconn, err := net.Dial("udp", dst)
	if err != nil {
		return
	}
	src := vconn.LocalAddr().String()
	addr, port, err := net.SplitHostPort(src)
	if err != nil {
		log.Printf("could parse local address (%v): %v", port, err)
		return
	}
	vp, _ := strconv.Atoi(port)

	log.Printf("%s -> %s", src, dst)

	resp := hkrtp.SetupEndpointsResponse{
		SessionId: req.SessionId,
		Status:    hkrtp.SessionStatusSuccess,
		AccessoryAddr: hkrtp.Addr{
			IPVersion:    req.ControllerAddr.IPVersion,
			IPAddr:       addr,
			VideoRtpPort: uint16(vp),
			AudioRtpPort: req.ControllerAddr.AudioRtpPort,
		},
		Video:     req.Video,
		Audio:     req.Audio,
		SsrcVideo: rand.Int31(),
		SsrcAudio: rand.Int31(),
	}

	maxSize := 1226
	if req.ControllerAddr.IPVersion == hkrtp.IPAddrVersionv4 {
		maxSize = 1376
	}

	vkey, err := unb64(req.Video.SrtpKey())
	if err != nil {
		return
	}

	c.Lock()
	defer c.Unlock()
	t := gortsplib.TransportTCP
	c.streams[string(req.SessionId)] = &stream{
		ctx: context.Background(),
		client: &gortsplib.Client{
			Transport: &t,
		},
		maxSize: maxSize,
		vconn:   vconn,
		vkey:    vkey,
		vssrc:   uint32(resp.SsrcVideo),
	}

	c.mgmt.SetupEndpoints.SetValue(must(tlv8.Marshal(resp)))
}

func (c *camera) selectStream(buf []byte) {
	c.Lock()
	defer c.Unlock()
	var cfg hkrtp.StreamConfiguration
	err := tlv8.Unmarshal(buf, &cfg)
	if err != nil {
		log.Printf("could not unmarshal tlv8: %s", err)
		return
	}

	s, ok := c.streams[string(cfg.Command.Identifier)]
	if !ok {
		log.Printf("unknown id %s", b64(cfg.Command.Identifier))
		return
	}

	switch cfg.Command.Type {
	case hkrtp.SessionControlCommandTypeStart:
		log.Printf("start %s", b64(cfg.Command.Identifier))
		ctx, cancel := context.WithCancel(s.ctx)
		s.cancel = cancel
		s.start(ctx, c.upstreamURL)
	case hkrtp.SessionControlCommandTypeSuspend:
		log.Printf("suspend %s", b64(cfg.Command.Identifier))
	case hkrtp.SessionControlCommandTypeResume:
		log.Printf("resume %s", b64(cfg.Command.Identifier))
	case hkrtp.SessionControlCommandTypeReconfigure:
		log.Printf("reconfigure %s", b64(cfg.Command.Identifier))
	case hkrtp.SessionControlCommandTypeEnd:
		log.Printf("stop %s", b64(cfg.Command.Identifier))
		if s.cancel != nil {
			s.cancel()
			s.client.Close()
			s.vconn.Close()
		}
		delete(c.streams, string(cfg.Command.Identifier))
	default:
		log.Printf("unknown command: %d", cfg.Command.Type)
	}
}

func (s *stream) start(ctx context.Context, url string) {
	u, err := base.ParseURL(url)
	if err != nil {
		return
	}

	err = s.client.Start(u.Scheme, u.Host)
	if err != nil {
		return
	}

	desc, _, err := s.client.Describe(u)
	if err != nil {
		return
	}

	var h *format.H264
	m := desc.FindFormat(&h)
	if m == nil {
		return
	}

	_, err = s.client.Setup(desc.BaseURL, m, 0, 0)
	if err != nil {
		return
	}

	dec, err := h.CreateDecoder()
	if err != nil {
		return
	}

	enc, err := h.CreateEncoder()
	if err != nil {
		return
	}
	enc.PacketizationMode = 1
	enc.PayloadType = 99
	enc.PayloadMaxSize = s.maxSize
	enc.SSRC = &s.vssrc
	enc.Init()

	txctx, err := srtp.CreateContext(s.vkey[:16], s.vkey[16:], srtp.ProtectionProfileAes128CmHmacSha1_80, srtp.SRTPNoReplayProtection())
	if err != nil {
		return
	}
	lastReport := time.Now()
	packetCount := uint32(0)
	octetCount := uint32(0)
	s.client.OnPacketRTP(m, h, func(pkt *rtp.Packet) {
		au, err := dec.Decode(pkt)
		if err != nil {
			if err != rtph264.ErrNonStartingPacketAndNoPrevious && err != rtph264.ErrMorePacketsNeeded {
				log.Printf("err: %v", err)
			}
			return
		}
		// prepend sps & pps in case the camera doesn't, like axis cameras.
		pp, err := enc.Encode(append([][]byte{h.SPS, h.PPS}, au...))
		if err != nil {
			log.Printf("err: %v", err)
			return
		}
		buf := make([]byte, 1500) // TODO pool bufs
		for _, p := range pp {
			p.Header.Timestamp = pkt.Header.Timestamp
			pbuf, err := p.Marshal()
			if err != nil {
				log.Printf("error encoding rtp packet: %v", err)
				s.client.Close()
				return
			}
			buf, err = txctx.EncryptRTP(buf, pbuf, &p.Header)
			if err != nil {
				log.Printf("error encrypting rtp packet: %v", err)
				s.client.Close()
				return
			}
			_, err = s.vconn.Write(buf)
			if err != nil {
				log.Printf("error writing rtp packet: %v", err)
				s.client.Close()
				return
			}
			packetCount++
			octetCount += uint32(len(p.Payload))
		}

		now := time.Now()
		if now.Sub(lastReport) > 5*time.Second && len(pp) > 0 {
			lastReport = now
			sr := rtcp.SenderReport{
				SSRC:        s.vssrc,
				NTPTime:     uint64(time.Now().Unix()),
				RTPTime:     pp[0].Header.Timestamp,
				PacketCount: packetCount,
				OctetCount:  octetCount,
			}
			b, err := sr.Marshal()
			if err != nil {
				log.Printf("error encoding rtcp packet: %v", err)
				s.client.Close()
				return
			}
			buf, err = txctx.EncryptRTCP(buf, b, nil)
			if err != nil {
				log.Printf("error encrypting rtcp packet: %v", err)
				s.client.Close()
				return
			}
			_, err = s.vconn.Write(buf)
			if err != nil {
				log.Printf("error writing rtcp packet: %v", err)
				s.client.Close()
				return
			}

		}
	})

	_, err = s.client.Play(nil)
	if err != nil {
		return
	}

	// discard incoming rtcp packets.
	go io.Copy(io.Discard, s.vconn)
}

var (
	b64   = base64.RawStdEncoding.EncodeToString
	unb64 = base64.RawStdEncoding.DecodeString
)

func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}
