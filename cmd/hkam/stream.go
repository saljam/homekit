package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"strconv"
	"time"

	"github.com/bluenviron/gortsplib/v4"
	"github.com/bluenviron/gortsplib/v4/pkg/base"
	"github.com/bluenviron/gortsplib/v4/pkg/description"
	"github.com/bluenviron/gortsplib/v4/pkg/format"
	"github.com/bluenviron/gortsplib/v4/pkg/format/rtph264"
	hkrtp "github.com/brutella/hap/rtp"
	"github.com/brutella/hap/tlv8"
	"github.com/pion/rtcp"
	"github.com/pion/rtp"
	"github.com/pion/srtp/v3"
)

type stream struct {
	client  *gortsplib.Client
	maxSize int
	ctx     context.Context
	cancel  func()

	// video rtp state
	vconn net.Conn
	vssrc uint32
	vkey  []byte

	// audio rtp state
	aconn net.Conn
	assrc uint32
	akey  []byte
}

func (c *camera) setup(buf []byte) {
	var req hkrtp.SetupEndpoints
	err := tlv8.Unmarshal(buf, &req)
	if err != nil {
		log.Printf("could not unmarshal tlv8: %v", err)
		return
	}

	log.Printf("setup endpoints %v", b64(req.SessionId))

	vdst := fmt.Sprintf("%v:%v", req.ControllerAddr.IPAddr, req.ControllerAddr.VideoRtpPort)
	vconn, err := net.Dial("udp", vdst)
	if err != nil {
		return
	}
	addr, vport, err := net.SplitHostPort(vconn.LocalAddr().String())
	if err != nil {
		log.Printf("could parse local address (%v): %v", vport, err)
		return
	}
	vp, _ := strconv.Atoi(vport)
	log.Printf("video: %s:%s -> %s", addr, vport, vdst)

	adst := fmt.Sprintf("%v:%v", req.ControllerAddr.IPAddr, req.ControllerAddr.AudioRtpPort)
	aconn, err := net.Dial("udp", adst)
	if err != nil {
		return
	}
	_, aport, err := net.SplitHostPort(aconn.LocalAddr().String())
	if err != nil {
		log.Printf("could parse local address (%v): %v", aport, err)
		return
	}
	ap, _ := strconv.Atoi(aport)
	log.Printf("audio: %s:%s -> %s", addr, aport, adst)

	resp := hkrtp.SetupEndpointsResponse{
		SessionId: req.SessionId,
		Status:    hkrtp.SessionStatusSuccess,
		AccessoryAddr: hkrtp.Addr{
			IPVersion:    req.ControllerAddr.IPVersion,
			IPAddr:       addr,
			VideoRtpPort: uint16(vp),
			AudioRtpPort: uint16(ap),
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

	akey, err := unb64(req.Audio.SrtpKey())
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

		aconn: aconn,
		akey:  akey,
		assrc: uint32(resp.SsrcAudio),
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
		s.start(ctx, c.streamURL)
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

	s.proxyVideo(desc)

	_, err = s.client.Play(nil)
	if err != nil {
		return
	}
}

func (s *stream) proxyVideo(desc *description.Session) {
	var h *format.H264
	m := desc.FindFormat(&h)
	if m == nil {
		return
	}

	_, err := s.client.Setup(desc.BaseURL, m, 0, 0)
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

	// discard incoming rtcp packets.
	go io.Copy(io.Discard, s.vconn)
}

type GetStreamURI struct {
	XMLName      string `xml:"trt:GetStreamUri"`
	ProfileToken string `xml:"trt:ProfileToken"`
	Stream       string `xml:"trt:StreamSetup>tt:Stream"`
	Protocol     string `xml:"trt:StreamSetup>tt:Transport>tt:Protocol"`
}

type GetStreamURIResponse struct {
	MediaURI string `xml:"MediaUri>Uri"`
}

func (c *camera) getStreamURL() error {
	mediaURL, err := c.GetServiceURL("http://www.onvif.org/ver10/media/wsdl")
	if err != nil {
		return err
	}

	token, err := c.GetProfile()
	if err != nil {
		return err
	}

	u := &GetStreamURIResponse{}
	err = c.do(&Request{
		URL:        mediaURL,
		Namespaces: namespaces,
		Body: &GetStreamURI{
			ProfileToken: token,
			Stream:       "RTP-Unicast",
			Protocol:     "RTSP",
		},
	}, u)
	if err != nil {
		return err
	}

	c.streamURL = u.MediaURI

	return nil
}
