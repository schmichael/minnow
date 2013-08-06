package main

import (
	"flag"
	"io/ioutil"
	"log"
	"net"
	"os"

	"github.com/schmichael/minnow"
)

var host = flag.String("host", "localhost:9876", "host and port of winnower")
var secret = flag.String("secret", "", "shared secret (required)")
var message = flag.String("message", "", "message as a string (otherwise stdin is used)")

func main() {
	var err error
	var m []byte
	flag.Parse()

	if *secret == "" {
		flag.Usage()
		log.Fatalf("-secret required to be set")
	}

	if *message == "" {
		m, err = ioutil.ReadAll(os.Stdin)
		if err != nil {
			log.Fatalf("Unable to read from stdin: %v", err)
		}
	} else {
		m = []byte(*message)
	}

	err = WriteMessage(m, []byte(*secret))

	if err != nil {
		log.Fatalf("Failed to send message: %+v", err)
	}
}

func WriteMessage(message []byte, secret []byte) error {
	var err error

	conn, err := net.Dial("tcp", *host)

	if err != nil {
		log.Fatalf("Connection failed: %+v", err)
	}

	rs := minnow.NewMessageWriteCloser(secret, conn)
	_, err = rs.Write(message)
	if err != nil {
		return err
	}
	err = rs.Close()
	return err
}
