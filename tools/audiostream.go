//go:build ignore

package main

import (
	"flag"
	"fmt"
	"log"

	"github.com/bluenviron/gortsplib/v4"
	"github.com/bluenviron/gortsplib/v4/pkg/base"
	"github.com/bluenviron/gortsplib/v4/pkg/description"
	"github.com/bluenviron/gortsplib/v4/pkg/format"
	"github.com/pion/rtp"
)

func main() {
	flag.Parse()
	u, err := base.ParseURL(flag.Arg(0))
	if err != nil {
		log.Fatal(err)
	}

	t := gortsplib.TransportTCP
	client := &gortsplib.Client{
		Transport: &t,
	}

	err = client.Start(u.Scheme, u.Host)
	if err != nil {
		log.Fatal(err)
	}

	desc, _, err := client.Describe(u)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(desc.Medias[0].Formats[0].Codec())

	play(client, desc)

	_, err = client.Play(nil)
	if err != nil {
		return
	}
	select {}
}

func play(client *gortsplib.Client, desc *description.Session) {
	var h *format.G711
	m := desc.FindFormat(&h)
	if m == nil {
		log.Printf("no fmt")
		return
	}

	_, err := client.Setup(desc.BaseURL, m, 0, 0)
	if err != nil {
		log.Printf("err: %v", err)
		return
	}

	dec, err := h.CreateDecoder()
	if err != nil {
		log.Printf("err: %v", err)
		return
	}

	log.Println(dec)

	/*
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
	*/

	client.OnPacketRTP(m, h, func(pkt *rtp.Packet) {
		ss, err := dec.Decode(pkt)
		if err != nil {
			log.Printf("err: %v", err)
			return
		}

		fmt.Printf("packet: %v bytes\n", len(ss))

		// prepend sps & pps in case the camera doesn't, like axis cameras.
		/*
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
			}

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
		*/
	})

}
