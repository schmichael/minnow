package main

import (
	"crypto/rand"
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
	raw := []byte(message)
	fakesecret := make([]byte, 64)
	fakedata := make([]byte, 1)

	rand.Read(fakesecret[0:64])

	conn, err := net.Dial("tcp", *host)
	defer conn.Close()

	if err != nil {
		log.Fatalf("Connection failed: %+v", err)
	}

	rs := minnow.NewStream(conn, secret)
	fs := minnow.NewStream(conn, fakesecret)

	for i, v := range raw {
		// Send the real packet
		bytev := []byte{v}

		err = rs.WritePacket(bytev, int32(i))
		if err != nil {
			return err
		}

		log.Printf("Sent good packet: %d %s", i, string(v))

		// Send the chaf packet
		//FIXME Obviously always sending the chaf second makes this trivial to break
		rand.Read(fakedata[0:1])
		err = fs.WritePacket(fakedata, int32(i))
		if err != nil {
			return err
		}
		log.Printf("Sent chaf packet: %d %v", i, fakedata)
	}

	return err
}
