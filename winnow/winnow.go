package main

import (
	"flag"
	"github.com/schmichael/minnow"
	"log"
	"net"
)

var bind = flag.String("bind", "localhost:9876", "host and port to bind to")
var secret = flag.String("secret", "", "shared secret (required)")

func main() {
	flag.Parse()

	if *secret == "" {
		flag.Usage()
		log.Fatalf("-secret required to be set")
	}

	ln, err := net.Listen("tcp", *bind)
	if err != nil {
		log.Fatalf("Error binding to socket: %+v", err)
	}
	log.Printf("Listening on: %s", *bind)
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Fatalf("Error on incoming connection: %+v\n", err)
		}
		r := minnow.NewMessageReader([]byte(*secret), conn)

		go func() {
			m := r.ReadAll()
			println(string(m))
		}()
	}
}
