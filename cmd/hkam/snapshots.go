package main

import (
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"

	"github.com/brutella/hap"
)

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
	if !(0 <= index && index < len(cameras)) {
		log.Printf("/resource: unknown accessory id: %v", msg.AID)
		http.Error(w, "unexpected id", http.StatusBadRequest)
		return
	}

	cameras[index].handleSnapshot(w, r)
}

func (c *camera) handleSnapshot(w http.ResponseWriter, r *http.Request) {
	if c.snapshotURL == "" {
		return
	}

	upstream, err := c.hclient.Get(c.snapshotURL)
	if err != nil {
		log.Printf("couldn't fetch snapshot: %v", err)
		return
	}
	defer upstream.Body.Close()

	for k, v := range upstream.Header {
		for _, vv := range v {
			w.Header().Add(k, vv)
		}
	}
	w.WriteHeader(upstream.StatusCode)
	io.Copy(w, upstream.Body)
}

type GetProfiles struct {
	XMLName string `xml:"trt:GetProfiles"`
}

type GetProfilesResponse struct {
	Profiles []struct {
		Token string `xml:"token,attr"`
	} `xml:"Profiles"`
}

// GetProfile gets the first onvif profile token.
func (c *camera) GetProfile() (string, error) {
	mediaURL, err := c.GetServiceURL("http://www.onvif.org/ver10/media/wsdl")
	if err != nil {
		return "", err
	}

	p := &GetProfilesResponse{}
	err = c.do(&Request{
		URL:        mediaURL,
		Namespaces: namespaces,
		Body:       &GetProfiles{},
	}, p)
	if err != nil {
		return "", err
	}
	if len(p.Profiles) == 0 {
		return "", errors.New("no profiles")
	}

	return p.Profiles[0].Token, nil
}

type GetSnapshotURI struct {
	XMLName      string `xml:"trt:GetSnapshotUri"`
	ProfileToken string `xml:"trt:ProfileToken"`
}

type GetSnapshotURIResponse struct {
	MediaURI string `xml:"MediaUri>Uri"`
}

func (c *camera) getSnapshotURL() error {
	mediaURL, err := c.GetServiceURL("http://www.onvif.org/ver10/media/wsdl")
	if err != nil {
		return err
	}

	token, err := c.GetProfile()
	if err != nil {
		return err
	}

	u := &GetSnapshotURIResponse{}
	err = c.do(&Request{
		URL:        mediaURL,
		Namespaces: namespaces,
		Body: &GetSnapshotURI{
			ProfileToken: token,
		},
	}, u)
	if err != nil {
		return err
	}

	c.snapshotURL = u.MediaURI

	return nil
}
