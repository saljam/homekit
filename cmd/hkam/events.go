package main

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/korylprince/go-onvif/soap"
)

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
				c.doorbell.ProgrammableSwitchEvent.SetValue(0)
			}
		}
	}
}

// lazily use one set of namespaces for all requests.
var namespaces = soap.Namespaces{
	"tev": "http://www.onvif.org/ver10/events/wsdl",
	"wsa": "http://www.w3.org/2005/08/addressing",
	"tds": "http://www.onvif.org/ver10/device/wsdl",
	"trt": "http://www.onvif.org/ver10/media/wsdl",
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

func (c *onvifClient) GetServiceURL(namespace string) (string, error) {
	svcs := &GetServicesResponse{}
	err := c.do(&Request{
		URL:        fmt.Sprintf("http://%s/onvif/device_service", c.addr),
		Namespaces: namespaces,
		Body:       &GetServices{IncludeCapability: false},
	}, svcs)
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

type CreatePullPointSubscription struct {
	XMLName string `xml:"tev:CreatePullPointSubscription"`
}

type CreatePullPointSubscriptionResponse struct {
	Address             string `xml:"SubscriptionReference>Address"`
	ReferenceParameters struct {
		InnerXML string `xml:",innerxml"`
	} `xml:"SubscriptionReference>ReferenceParameters,omitempty"`
	CurrentTime     string `xml:"CurrentTime"`
	TerminationTime string `xml:"TerminationTime"`
}

func (c *onvifClient) CreatePullPoint(addr string) (*CreatePullPointSubscriptionResponse, error) {
	pullpoint := &CreatePullPointSubscriptionResponse{}
	err := c.do(&Request{
		URL:        addr,
		Namespaces: namespaces,
		Body:       &CreatePullPointSubscription{},
	}, pullpoint)
	return pullpoint, err
}

type PullMessages struct {
	XMLName      string `xml:"tev:PullMessages"`
	Timeout      string `xml:"tev:Timeout"`
	MessageLimit int    `xml:"tev:MessageLimit"`
}

type PullMessagesResponse struct {
	XMLName              string `xml:"PullMessagesResponse"`
	CurrentTime          string `xml:"CurrentTime"`
	TerminationTime      string `xml:"TerminationTime"`
	NotificationMessages []struct {
		Source []struct {
			Name  string `xml:"Name,attr"`
			Value string `xml:"Value,attr"`
		} `xml:"Message>Source>SimpleItem"`
		Data []struct {
			Name  string `xml:"Name,attr"`
			Value string `xml:"Value,attr"`
		} `xml:"Message>Data>SimpleItem"`
	} `xml:"NotificationMessage>Message"`
}

func (c *onvifClient) PullMessages(addr string, pullpoint *CreatePullPointSubscriptionResponse) (state map[string]bool, err error) {
	msgs := &PullMessagesResponse{}
	err = c.do(&Request{
		URL:        addr,
		Namespaces: namespaces,
		Header: Header{
			To:                  pullpoint.Address,
			ReferenceParameters: pullpoint.ReferenceParameters.InnerXML,
		},
		Body: &PullMessages{
			Timeout:      "PT30S",
			MessageLimit: 10,
		},
	}, msgs)
	if err != nil {
		return nil, err
	}

	state = make(map[string]bool)
	for _, msg := range msgs.NotificationMessages {
		for _, src := range msg.Source {
			if src.Name == "Source" || src.Name == "InputToken" {
				for _, dat := range msg.Data {
					if dat.Name == "State" || dat.Name == "LogicalState" {
						b, err := strconv.ParseBool(dat.Value)
						if err == nil {
							state[src.Value] = b
						}
					}
				}
			}
		}
	}
	return
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

type onvifClient struct {
	addr     string
	security *soap.Security
}

func newONVIFClient(u string) (*onvifClient, error) {
	uu, err := url.Parse(u)
	if err != nil {
		return nil, fmt.Errorf("could not parse url (%v): %w", u, err)
	}
	c := &onvifClient{
		addr: uu.Host,
	}
	password, _ := uu.User.Password()
	if uu.User.Username() != "" && password != "" {
		s, err := soap.NewSecurity(uu.User.Username(), password)
		if err != nil {
			return nil, fmt.Errorf("could not create security header: %w", err)
		}
		c.security = s
	}
	return c, nil
}

func (c *onvifClient) do(request *Request, response any) error {
	request.Header.Security = c.security
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

	soapResp, err := http.Post(request.URL, "application/soap+xml", buf)
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
