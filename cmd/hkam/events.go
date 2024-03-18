package main

import (
	"log"
	"strconv"
	"time"
)

func (c *camera) subscribe(motionevent, doorbellevent string) {
	if motionevent == "" && doorbellevent == "" {
		return
	}

	for {
		eventsURL, err := c.GetServiceURL("http://www.onvif.org/ver10/events/wsdl")
		if err != nil {
			log.Printf("error pulling onvif events: %v", err)
			time.Sleep(2 * time.Minute)
			continue
		}

		pullpoint, err := c.CreatePullPoint(eventsURL)
		if err != nil {
			log.Printf("error pulling onvif events: %v", err)
			time.Sleep(2 * time.Minute)
			continue
		}

	inner:
		for {
			state, err := c.PullMessages(eventsURL, pullpoint)
			if err != nil {
				log.Printf("error pulling onvif events: %v", err)
				time.Sleep(2 * time.Minute)
				break inner
			}
			if motion, ok := state[motionevent]; ok {
				if motion {
					log.Println("motion detected")
				}
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

func (c *camera) CreatePullPoint(addr string) (*CreatePullPointSubscriptionResponse, error) {
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

func (c *camera) PullMessages(addr string, pullpoint *CreatePullPointSubscriptionResponse) (state map[string]bool, err error) {
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
