package main

import (
    "flag"
    "log"
    "crypto/hmac"
    "crypto/rand"
    "crypto/sha512"
    "encoding/binary"
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
    var mbuf [64]byte
    var m []byte
    var err error
    var n int
    raw := []byte(message)
    fakesecret := make([]byte, 64)
    fakedata := make([]byte, 1)

    rand.Read(fakesecret[0:64])

    realmac := hmac.New(sha512.New, secret)
    fakemac := hmac.New(sha512.New, fakesecret)

    conn, err := net.Dial("tcp", *peer)
    if err != nil {
        log.Fatalf("Connection failed: %+v", err)
    }

    for i, v := range raw {
        // Send the real packet
        bytev := []byte{v}
        realmac.Write(bytev)
        m = realmac.Sum(nil)

        for i, _ := range mbuf {
            mbuf[i] = m[i]
        }

        header := &minnow.PacketHeader{
            StreamId: 1,
            SequenceN: int32(i),
            Mac: mbuf,
            Size: int32(len(bytev)),
        }

        binary.Write(conn, binary.BigEndian, header)
        n, err = conn.Write(bytev)

        if n != len(bytev) {
            log.Fatalf("Whole packet didn't send and I'm lazy: %d out of %d", n, len(bytev))
        }
        if err != nil {
            return err
        }

        log.Printf("Sent good packet: %d %s", i, string(v))

        // Send the chaf packet
        //FIXME Obviously always sending the chaf second makes this trivial to break
        rand.Read(fakedata[0:1])
        fakemac.Write(fakedata)
        m = fakemac.Sum(nil)
        for i, _ := range mbuf {
            mbuf[i] = m[i]
        }

        header.Mac = mbuf
        header.Size = int32(len(fakedata))

        binary.Write(conn, binary.BigEndian, header)
        n, err = conn.Write(fakedata)

        if n != len(bytev) {
            log.Fatalf("Whole packet didn't send and I'm lazy: %d out of %d", n, len(bytev))
        }
        if err != nil {
            return err
        }
        log.Printf("Sent chaf packet: %d %v", i, fakedata)

        realmac.Reset()
        fakemac.Reset()
    }

    err = conn.Close()
    return err
}
