package main

import (
    "flag"
    "log"
    "crypto/rand"
    "net"
	"github.com/schmichael/minnow"
)

var peer = flag.String("peer", "localhost:9876", "gimme a host and port")

func main() {
    flag.Parse()

    message := "Hello Kyle!"
    secret := []byte("goduckyourself")
    err := WriteMessage(message, secret)

    if err != nil {
        log.Fatalf("You had one job: %+v", err)
    } else {
        log.Printf("You won")
    }
}

func WriteMessage(message string, secret []byte) error {
    var err error
    raw := []byte(message)
    fakesecret := make([]byte, 64)
    fakedata := make([]byte, 1)

    rand.Read(fakesecret[0:64])

    conn, err := net.Dial("tcp", *peer)
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
