//go:build ignore

package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	crand "crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net/http"
	"net/url"
	"strconv"
)

func main() {
	toggle := flag.Bool("toggle", false, "toggle gate state")
	username := flag.String("user", "", "username")
	password := flag.String("pass", "", "password")
	host := flag.String("host", "", "host address")
	flag.Parse()

	apiurl := fmt.Sprintf("http://%s/api.php", *host)

	s, _, code, err := getinfo(apiurl, *username, *password)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(s)

	if *toggle {
		activate(apiurl, *username, *password, code)
	}
}

func getinfo(apiurl, username, password string) (status, alive, apicode string, err error) {
	cmd, err := json.Marshal([]string{username, password, "info"})
	if err != nil {
		return
	}

	encoded, err := encode(username, password, cmd)
	if err != nil {
		return
	}

	u, err := url.ParseRequestURI(apiurl)
	if err != nil {
		return
	}
	params := url.Values{
		"data":  {encoded},
		"t":     {strconv.Itoa(rand.Intn(100000) + 1)},
		"token": {fmt.Sprintf("%x", sha1.Sum([]byte(username+"@ismartgate")))},
	}
	u.RawQuery = params.Encode()
	r, err := http.Get(u.String())
	if err != nil {
		return
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return
	}

	response, err := decode(username, password, body)
	if err != nil {
		return
	}

	fmt.Printf("%s\n", response)

	s := struct {
		Status  string `xml:"door1>status"`
		Alive   string `xml:"door1>alive"`
		APICode string `xml:"door1>apicode"`
	}{}
	xml.Unmarshal(response, &s)
	return s.Status, s.Alive, s.APICode, nil
}

func activate(apiurl, username, password, apicode string) error {
	cmd, err := json.Marshal([]string{username, password, "activate", "1", apicode})
	if err != nil {
		return err
	}

	encoded, err := encode(username, password, cmd)
	if err != nil {
		return err
	}

	u, err := url.ParseRequestURI(apiurl)
	if err != nil {
		return err
	}
	params := url.Values{
		"data":  {encoded},
		"t":     {strconv.Itoa(rand.Intn(100000) + 1)},
		"token": {fmt.Sprintf("%x", sha1.Sum([]byte(username+"@ismartgate")))},
	}
	u.RawQuery = params.Encode()
	_, err = http.Get(u.String())
	if err != nil {
		return err
	}
	// status code is useless - i often get 500s when it actually toggles the gate.
	return nil
}

// this hurt to write.
// derived from https://github.com/bdraco/ismartgate
func encode(username, password string, buf []byte) (string, error) {
	k := fmt.Sprintf("%x", sha1.Sum([]byte(username+password)))
	key := []byte(k[32:36] + "a" + k[7:10] + "!" + k[18:21] + "*#" + k[24:26])

	padding := aes.BlockSize - len(buf)%aes.BlockSize
	buf = append(buf, bytes.Repeat([]byte{byte(padding)}, padding)...)

	iv := make([]byte, aes.BlockSize/2)
	_, err := crand.Read(iv)
	if err != nil {
		return "", err
	}
	iv = make([]byte, aes.BlockSize/2) // remove
	iv = hex.AppendEncode(nil, iv)

	c, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	cbc := cipher.NewCBCEncrypter(c, iv)
	cbc.CryptBlocks(buf, buf)

	return string(iv) + base64.StdEncoding.EncodeToString(buf), nil
}

func decode(username, password string, buf []byte) ([]byte, error) {
	if len(buf) < aes.BlockSize {
		return nil, errors.New("too short")
	}

	k := fmt.Sprintf("%x", sha1.Sum([]byte(username+password)))
	key := []byte(k[32:36] + "a" + k[7:10] + "!" + k[18:21] + "*#" + k[24:26])

	iv := buf[:aes.BlockSize]
	buf, err := base64.StdEncoding.AppendDecode(nil, buf[aes.BlockSize:])
	if err != nil {
		return nil, err
	}

	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	cbc := cipher.NewCBCDecrypter(c, iv)
	cbc.CryptBlocks(buf, buf)

	padding := buf[len(buf)-1]
	return buf[:len(buf)-int(padding)], nil
}
