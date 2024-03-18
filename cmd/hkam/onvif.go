package main

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"strings"

	"github.com/korylprince/go-onvif/soap"
)

// lazily use one set of namespaces for all requests.
var namespaces = soap.Namespaces{
	"tev": "http://www.onvif.org/ver10/events/wsdl",
	"wsa": "http://www.w3.org/2005/08/addressing",
	"tds": "http://www.onvif.org/ver10/device/wsdl",
	"trt": "http://www.onvif.org/ver10/media/wsdl",
	"tt":  "http://www.onvif.org/ver10/schema",
}

type GetServices struct {
	XMLName           xml.Name `xml:"tds:GetServices"`
	IncludeCapability bool     `xml:"tds:IncludeCapability"`
}

type GetServicesResponse struct {
	Service []*struct {
		Namespace    string
		URL          string `xml:"XAddr"`
		VersionMajor int    `xml:"Version>Major"`
		VersionMinor int    `xml:"Version>Minor"`
	}
}

func (c *camera) GetServiceURL(namespace string) (string, error) {
	svcs := &GetServicesResponse{}
	err := c.do(&Request{
		URL:        c.onvifAddr,
		Namespaces: namespaces,
		Body:       &GetServices{IncludeCapability: false},
	}, svcs)
	if err != nil && strings.HasPrefix(c.onvifAddr, "https") {
		// fallback to plain http.
		// TODO remove this once we accept onvif urls in config.
		err = c.do(&Request{
			URL:        "http" + c.onvifAddr[5:],
			Namespaces: namespaces,
			Body:       &GetServices{IncludeCapability: false},
		}, svcs)
	}
	if err != nil {
		return "", fmt.Errorf("could not complete operation: %w", err)
	}
	for _, svc := range svcs.Service {
		if svc.Namespace == namespace {
			return svc.URL, nil
		}
	}
	return "", errors.New("service not found")
}

type Header struct {
	XMLName             xml.Name       `xml:"env:Header"`
	Security            *soap.Security `xml:",omitempty"`
	To                  string         `xml:"wsa:To,omitempty"`
	ReferenceParameters string         `xml:",innerxml"`
}

type Body struct {
	XMLName  xml.Name    `xml:"env:Body"`
	Fault    *soap.Fault `xml:",omitempty"`
	InnerXML []byte      `xml:",innerxml"`
}

type Envelope struct {
	Namespaces map[string]string `xml:"-"`
	Header     *Header
	Body       *soap.Body
}

type Request struct {
	URL        string
	Namespaces soap.Namespaces
	Header     Header
	Body       any
}

func (c *camera) do(request *Request, response any) error {
	if c.username != "" && c.password != "" {
		s, err := soap.NewSecurity(c.username, c.password)
		if err != nil {
			return fmt.Errorf("could not create security header: %w", err)
		}
		request.Header.Security = s
	}
	body, err := xml.Marshal(request.Body)
	if err != nil {
		return fmt.Errorf("could not marshal request: %w", err)
	}
	reqEnv := &Envelope{
		Namespaces: request.Namespaces,
		Header:     &request.Header,
		Body:       &soap.Body{InnerXML: body},
	}

	buf := bytes.NewBufferString(xml.Header)
	if err = xml.NewEncoder(buf).Encode(reqEnv); err != nil {
		return fmt.Errorf("could not marshal envelope: %w", err)
	}

	soapResp, err := c.hclient.Post(request.URL, "application/soap+xml", buf)
	if err != nil {
		return fmt.Errorf("could not POST request: %w", err)
	}
	defer soapResp.Body.Close()

	respEnv := new(soap.Envelope)
	if err = xml.NewDecoder(soapResp.Body).Decode(respEnv); err != nil {
		return fmt.Errorf("could not decode response: %w", err)
	}

	if respEnv.Body.Fault != nil {
		if respEnv.Body.Fault.IsUnauthorizedError() {
			return &soap.UnauthorizedError{Err: respEnv.Body.Fault}
		}
		return respEnv.Body.Fault
	}

	return respEnv.Body.Unmarshal(response)
}

// MarshalXML implements xml.Marshaler
func (e *Envelope) MarshalXML(enc *xml.Encoder, start xml.StartElement) error {
	start.Name = xml.Name{Local: "env:Envelope"}

	start.Attr = append(start.Attr, xml.Attr{Name: xml.Name{Local: "xmlns:env"}, Value: soap.NamespaceEnvelope})

	for name, val := range e.Namespaces {
		start.Attr = append(start.Attr, xml.Attr{Name: xml.Name{Local: "xmlns:" + name}, Value: val})
	}

	if err := enc.EncodeToken(start); err != nil {
		return fmt.Errorf("could not encode start token: %w", err)
	}

	if e.Header != nil {
		if err := enc.Encode(e.Header); err != nil {
			return fmt.Errorf("could not encode header: %w", err)
		}
	}

	if e.Body != nil {
		b := &Body{Fault: e.Body.Fault, InnerXML: e.Body.InnerXML}
		if err := enc.Encode(b); err != nil {
			return fmt.Errorf("could not encode body: %w", err)
		}
	}

	if err := enc.EncodeToken(xml.EndElement{Name: xml.Name{Local: "env:Envelope"}}); err != nil {
		return fmt.Errorf("could not encode end token: %w", err)
	}

	return nil
}
