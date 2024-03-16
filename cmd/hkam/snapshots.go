package main

import (
	"bytes"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os/exec"
	"time"

	"github.com/brutella/hap"
)

func (c *camera) fetchSnapshot() error {
	buf := &bytes.Buffer{}
	cmd := exec.Command("ffmpeg",
		"-rtsp_transport", "tcp",
		"-i", c.upstreamURL,
		"-f", "image2",
		"-frames:v", "1",
		"-",
	)
	cmd.Stdout = buf
	err := cmd.Run()
	if err != nil {
		return err
	}
	c.Lock()
	defer c.Unlock()
	c.snapshot = buf.Bytes()
	c.snapshotTime = time.Now()
	return nil
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
	if !(0 <= index && index < len(cameras)) {
		log.Printf("/resource: unknown accessory id: %v", msg.AID)
		http.Error(w, "unexpected id", http.StatusBadRequest)
		return
	}

	cameras[index].Lock()
	buf := cameras[index].snapshot
	ts := cameras[index].snapshotTime
	cameras[index].Unlock()

	if time.Since(ts) > 8*time.Second {
		cameras[index].fetchSnapshot()
		cameras[index].Lock()
		buf = cameras[index].snapshot
		ts = cameras[index].snapshotTime
		cameras[index].Unlock()
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
