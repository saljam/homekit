// command hkam bridges rtsp cameras to homekit.
//
// this uses ffmpeg for snapshots and expects it in $PATH.
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"github.com/brutella/hap"
	"github.com/brutella/hap/accessory"
	"github.com/brutella/hap/characteristic"
	hkrtp "github.com/brutella/hap/rtp"
	"github.com/brutella/hap/service"
	"github.com/brutella/hap/tlv8"
	"github.com/icholy/digest"
)

var (
	server  *hap.Server
	cameras []*camera
)

var (
	// TODO tofu self signed certs instead of this.
	insecuretls bool
)

func main() {
	log.SetFlags(0)
	log.SetPrefix("")
	pin := flag.String("pin", "", "homekit pin")
	flag.BoolVar(&insecuretls, "insecure", false, "skip verifying tls certificates")
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
	streams map[string]*stream

	// upstreamURL is the upstream rtsp:// video url.
	upstreamURL string

	// snapshotURL is the url to fetch jpeg snapshots from the camera.
	snapshotURL string

	// homekit api objects.
	a          *accessory.A
	mgmt       *service.CameraRTPStreamManagement
	mgmtActive *characteristic.Active
	microphone *service.Microphone
	doorbell   *service.Doorbell
	motion     *service.MotionSensor

	hclient *http.Client
}

func newCamera(name, upstream, motionevent, doorbellevent string) *camera {
	c := &camera{
		upstreamURL: upstream,
		streams:     map[string]*stream{},
		a:           accessory.New(accessory.Info{Name: name, Firmware: "0.0.1", Manufacturer: "aljammaz labs"}, accessory.TypeIPCamera),
		mgmt:        service.NewCameraRTPStreamManagement(),
		mgmtActive:  characteristic.NewActive(),
		hclient:     &http.Client{},
	}

	if insecuretls {
		c.hclient.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
	}

	u, err := url.Parse(upstream)
	if err != nil {
		log.Fatalf("cannot parse upstream url: %v", err)
	}
	if pwd, ok := u.User.Password(); ok {
		c.hclient.Transport = &digest.Transport{
			Username:  u.User.Username(),
			Password:  pwd,
			Transport: c.hclient.Transport,
		}
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
	c.mgmt.SupportedAudioStreamConfiguration.SetValue(must(tlv8.Marshal(hkrtp.AudioStreamConfiguration{
		Codecs: []hkrtp.AudioCodecConfiguration{
			{
				Type: hkrtp.AudioCodecType_Opus,
				Parameters: hkrtp.AudioCodecParameters{
					Channels:   1,
					Bitrate:    hkrtp.AudioCodecBitrateVariable,
					Samplerate: hkrtp.AudioCodecSampleRate24Khz,
				},
			},
		},
		ComfortNoise: false,
	})))
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

	// TODO lazily retry this if it fails, and respect lifetime parameters in
	// the onvif response.
	err = c.getSnapshotURL()
	if err != nil {
		log.Printf("could not get snapshot url for %v: %v", name, err)
	}

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

func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}
