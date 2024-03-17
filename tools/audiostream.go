//go:build ignore

package main

import (
	"flag"
	"fmt"
	"log"

	"github.com/bluenviron/gortsplib/v4"
	"github.com/bluenviron/gortsplib/v4/pkg/base"
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
}
