// command hkam proxies rtsp cameras as homekit devices.
//
// this uses ffmpeg and expects it in $PATH.
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
		a := newRTSPCamera(fmt.Sprintf("cam-%d", i+1), url)
		a.Id = uint64(i + 2)
		as = append(as, a)
	}

	bridge := accessory.NewBridge(accessory.Info{Name: "cams", Manufacturer: "aljammaz labs"}).A
	bridge.Id = 1

	var err error
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

type rtspProxy struct {
	sync.Mutex
	// upstreamURL is the upstream rtsp:// video URL.
	upstreamURL string
	streams     map[string]*stream
	mgmt        *service.CameraRTPStreamManagement
}

type stream struct {
	setup  rtp.SetupEndpoints
	ssrc   int
	ctx    context.Context
	cancel func()
}

func newRTSPCamera(name, upstream string) *accessory.A {
	cam := accessory.NewCamera(accessory.Info{Name: name, Firmware: "0.0.1", Manufacturer: "aljammaz labs"})

	c1 := rtspProxy{
		upstreamURL: upstream,
		streams:     map[string]*stream{},
		mgmt:        cam.StreamManagement1,
	}
	c1.mgmt.StreamingStatus.SetValue(mustTVL8Marshal(rtp.StreamingStatus{rtp.StreamingStatusAvailable}))
	c1.mgmt.SupportedRTPConfiguration.SetValue(mustTVL8Marshal(rtp.NewConfiguration(rtp.CryptoSuite_AES_CM_128_HMAC_SHA1_80)))
	c1.mgmt.SupportedVideoStreamConfiguration.SetValue(mustTVL8Marshal(rtp.DefaultVideoStreamConfiguration()))
	c1.mgmt.SupportedAudioStreamConfiguration.SetValue(mustTVL8Marshal(rtp.DefaultAudioStreamConfiguration()))
	c1.mgmt.SelectedRTPStreamConfiguration.OnValueRemoteUpdate(c1.selectRTPStreamConfig)
	c1.mgmt.SetupEndpoints.OnValueUpdate(c1.setupEndpoints)

	c2 := rtspProxy{
		upstreamURL: upstream,
		streams:     map[string]*stream{},
		mgmt:        cam.StreamManagement2,
	}
	c2.mgmt.StreamingStatus.SetValue(mustTVL8Marshal(rtp.StreamingStatus{rtp.StreamingStatusAvailable}))
	c2.mgmt.SupportedRTPConfiguration.SetValue(mustTVL8Marshal(rtp.NewConfiguration(rtp.CryptoSuite_AES_CM_128_HMAC_SHA1_80)))
	c2.mgmt.SupportedVideoStreamConfiguration.SetValue(mustTVL8Marshal(rtp.DefaultVideoStreamConfiguration()))
	c2.mgmt.SupportedAudioStreamConfiguration.SetValue(mustTVL8Marshal(rtp.DefaultAudioStreamConfiguration()))
	c2.mgmt.SelectedRTPStreamConfiguration.OnValueRemoteUpdate(c2.selectRTPStreamConfig)
	c2.mgmt.SetupEndpoints.OnValueUpdate(c2.setupEndpoints)

	return cam.A
}

func (c *rtspProxy) selectRTPStreamConfig(buf []byte) {
	c.Lock()
	defer c.Unlock()
	var cfg rtp.StreamConfiguration
	err := tlv8.Unmarshal(buf, &cfg)
	if err != nil {
		log.Printf("could not unmarshal tlv8: %s", err)
		return
	}

	s := c.streams[string(cfg.Command.Identifier)]
	b64 := base64.RawStdEncoding.EncodeToString

	switch cfg.Command.Type {
	case rtp.SessionControlCommandTypeStart:
		log.Printf("start %s", b64(cfg.Command.Identifier))
		ctx, cancel := context.WithCancel(s.ctx)
		s.cancel = cancel
		s.startStream(ctx, cfg, c.upstreamURL)
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
		delete(c.streams, string(cfg.Command.Identifier))
		c.mgmt.SetupEndpoints.Bytes.SetValue(mustTVL8Marshal(rtp.StreamingStatus{rtp.StreamingStatusAvailable}))
	default:
		log.Printf("unknown command: %d", cfg.Command.Type)
	}
}

func (c *rtspProxy) setupEndpoints(new, old []byte, r *http.Request) {
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

	c.Lock()
	defer c.Unlock()
	c.streams[string(req.SessionId)] = &stream{
		setup: req,
		ssrc:  int(resp.SsrcVideo),
		ctx:   context.Background(),
	}

	c.mgmt.SetupEndpoints.SetValue(mustTVL8Marshal(resp))
}

func (s *stream) startStream(ctx context.Context, cfg rtp.StreamConfiguration, url string) {
	mtu := 1228
	if s.setup.ControllerAddr.IPVersion == rtp.IPAddrVersionv4 {
		mtu = 1378
	}

	profile := "baseline"
	for _, p := range cfg.Video.CodecParams.Profiles {
		if p.Id == rtp.VideoCodecProfileMain {
			profile = "main"
		}
		if p.Id == rtp.VideoCodecProfileHigh {
			profile = "high"
		}
	}

	level := "3.1"
	for _, p := range cfg.Video.CodecParams.Levels {
		if p.Level == rtp.VideoCodecLevel3_2 {
			level = "3.2"
		}
		if p.Level == rtp.VideoCodecLevel4 {
			level = "4.0"
		}
	}

	log.Printf("stream requested: (%s %s) %dfps %dx%d %dkb/s mtu:%d", profile, level, cfg.Video.Attributes.Framerate, cfg.Video.Attributes.Width, cfg.Video.Attributes.Height, cfg.Video.RTP.Bitrate, cfg.Video.RTP.MTU)

	cmd := exec.CommandContext(ctx, "ffmpeg",
		"-hide_banner",
		"-rtsp_transport", "tcp",

		// as is:
		"-i", url,
		"-c", "copy", "-an",

		// axis:
		//"-i", fmt.Sprintf("%s?videocodec=h264&videozstrength=off&fps=%d&h264profile=main&resolution=%dx%d", url, cfg.Video.Attributes.Framerate, cfg.Video.Attributes.Width, cfg.Video.Attributes.Height),
		// saving in .ts then streaming that works...
		// ffmpeg -y -use_wallclock_as_timestamps 1 -hide_banner -t 10s -rtsp_transport tcp -skip_frame nokey -i 'rtsp://.../axis-media/media.amp?resolution=1280x720' -codec:v copy codec.ts
		//"-re", "-stream_loop", "-1", "-i", "/home/s/codec.ts",
		//"-codec:v", "copy",

		// reencode:
		//"-i", fmt.Sprintf("%s?videocodec=h264&videozstrength=off&fps=%d&h264profile=high&resolution=%dx%d", url, cfg.Video.Attributes.Framerate, cfg.Video.Attributes.Width, cfg.Video.Attributes.Height),
		//"-codec:v", "h264_v4l2m2m", "-pix_fmt", "yuv420p",
		//"-video_size", fmt.Sprintf("%d:%d", cfg.Video.Attributes.Width, cfg.Video.Attributes.Height),
		//"-framerate", fmt.Sprintf("%d", cfg.Video.Attributes.Framerate),
		//"-b:v", fmt.Sprintf("%dk", cfg.Video.RTP.Bitrate),

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
