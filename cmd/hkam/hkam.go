// command hkam bridges rtsp cameras to homekit.
//
// this uses ffmpeg for snapshots and expects it in $PATH.
package main

import (
	"context"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
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
	server  *hap.Server
	cameras []*camera
)

func main() {
	log.SetFlags(0)
	log.SetPrefix("")
	pin := flag.String("pin", "", "homekit pin")
	statedir := flag.String("state", filepath.Join(os.Getenv("HOME"), "hk", filepath.Base(os.Args[0])), "state directory")
	flag.Parse()

	as := []*accessory.A{}
	for i, arg := range flag.Args() {
		parts := strings.Split(arg, ",")
		var url, doorbellevent, motionevent string
		if len(parts) == 3 {
			doorbellevent = parts[0]
			motionevent = parts[1]
			url = parts[2]
		} else if len(parts) == 1 {
			url = parts[0]
		} else {
			log.Fatalf("could not parse url %d: %v", i, arg)
		}
		c := newCamera(fmt.Sprintf("%d", i+1), url, motionevent, doorbellevent)
		c.a.Id = uint64(i + 2)
		as = append(as, c.a)
		cameras = append(cameras, c)
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
		SerialNumber: string(id),
		Manufacturer: "aljammaz labs",
	}).A
	bridge.Id = 1

	server, err = hap.NewServer(hap.NewFsStore(*statedir), bridge, as...)
	if err != nil {
		log.Fatalf("could not make hap server: %v", err)
	}
	server.Pin = *pin

	server.ServeMux().HandleFunc("/resource", handleSnapshot)

	log.Fatal(server.ListenAndServe(context.Background()))
}

type camera struct {
	// streams is the map of live rtp streams.
	sync.Mutex
	streams      map[string]*stream
	snapshot     []byte
	snapshotTime time.Time

	// upstreamURL is the upstream rtsp:// video URL.
	upstreamURL string

	// homekit api objects.
	a          *accessory.A
	mgmt       *service.CameraRTPStreamManagement
	mgmtActive *characteristic.Active
	microphone *service.Microphone
	doorbell   *service.Doorbell
	motion     *service.MotionSensor
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

func newCamera(name, upstream, motionevent, doorbellevent string) *camera {
	c := &camera{
		upstreamURL: upstream,
		streams:     map[string]*stream{},
		a:           accessory.New(accessory.Info{Name: name, Firmware: "0.0.1", Manufacturer: "aljammaz labs"}, accessory.TypeIPCamera),
		mgmt:        service.NewCameraRTPStreamManagement(),
		mgmtActive:  characteristic.NewActive(),
	}
	c.mgmt.StreamingStatus.SetValue(must(tlv8.Marshal(hkrtp.StreamingStatus{hkrtp.StreamingStatusAvailable})))
	c.mgmt.SupportedRTPConfiguration.SetValue(must(tlv8.Marshal(hkrtp.NewConfiguration(hkrtp.CryptoSuite_AES_CM_128_HMAC_SHA1_80))))
	c.mgmt.SupportedVideoStreamConfiguration.SetValue(must(tlv8.Marshal(hkrtp.VideoStreamConfiguration{
		Codecs: []hkrtp.VideoCodecConfiguration{
			{
				Type: hkrtp.VideoCodecType_H264,
				Parameters: hkrtp.VideoCodecParameters{
					Profiles: []hkrtp.VideoCodecProfile{
						{hkrtp.VideoCodecProfileMain},
					},
					Levels: []hkrtp.VideoCodecLevel{
						{hkrtp.VideoCodecLevel3_1},
					},
					Packetizations: []hkrtp.VideoCodecPacketization{
						{hkrtp.VideoCodecPacketizationModeNonInterleaved},
					},
				},
				Attributes: []hkrtp.VideoCodecAttributes{
					{1920, 1080, 30}, // 1080p
					{1280, 720, 30},  // 720p
				},
			},
		},
	})))
	c.mgmt.SupportedAudioStreamConfiguration.SetValue(must(tlv8.Marshal(hkrtp.DefaultAudioStreamConfiguration())))
	c.mgmt.SelectedRTPStreamConfiguration.OnValueRemoteUpdate(c.selectStream)
	c.mgmt.SetupEndpoints.OnValueRemoteUpdate(c.setup)
	c.a.AddS(c.mgmt.S)

	if motionevent != "" {
		c.motion = service.NewMotionSensor()
		c.a.AddS(c.motion.S)
	}

	if doorbellevent != "" {
		c.doorbell = service.NewDoorbell()
		c.a.AddS(c.doorbell.S)

		c.microphone = service.NewMicrophone()
		//c.a.AddS(c.microphone.S)
	}
	go c.subscribe(motionevent, doorbellevent)

	// HomeKit Secure Video things:
	/*
		// TODO RTPStreamManagement Active characteristic
		//c.mgmt.AddC(c.mgmtActive.C)

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

	return c
}

func (c *camera) subscribe(motionevent, doorbellevent string) {
	if motionevent == "" && doorbellevent == "" {
		return
	}

	oc, err := newONVIFClient(c.upstreamURL)
	if err != nil {
		log.Printf("onvif events disabled: %v", err)
		return
	}

	for {
		eventsURL, err := oc.GetServiceURL("http://www.onvif.org/ver10/events/wsdl")
		if err != nil {
			log.Printf("error pulling onvif events: %v", err)
			time.Sleep(2 * time.Minute)
			continue
		}

		pullpoint, err := oc.CreatePullPoint(eventsURL)
		if err != nil {
			log.Printf("error pulling onvif events: %v", err)
			time.Sleep(2 * time.Minute)
			continue
		}

	inner:
		for {
			state, err := oc.PullMessages(eventsURL, pullpoint)
			if err != nil {
				log.Printf("error pulling onvif events: %v", err)
				time.Sleep(2 * time.Minute)
				break inner
			}
			if motion, ok := state[motionevent]; ok {
				log.Println("motion detected")
				c.motion.MotionDetected.SetValue(motion)
			}
			if pressed, ok := state[doorbellevent]; ok && pressed {
				//0 ”Single Press”
				//1 ”Double Press”
				//2 ”Long Press”
				log.Println("doorbell pressed")
				c.fetchSnapshot()
				c.doorbell.ProgrammableSwitchEvent.SetValue(0)
			}
		}
	}
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
