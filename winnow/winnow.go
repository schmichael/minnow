package main

import (
    "flag"
    "log"
    "crypto/hmac"
    "crypto/sha512"
    "encoding/binary"
    "net"
    "github.com/schmichael/minnow"
    "io"
)

// Creates an accumulator of new messages. Takes a function to call when valid data is accumulated
// Returns a function to call with new messages
func messageValidator(secret string, valid chan []byte) func(*minnow.Packet) {
	return func(m *minnow.Packet) {
		if m == nil {
			valid <-nil
		} else if hashData(secret, m.Payload) == m.Header.Mac {
			valid <-m.Payload
		}
	}
}

func hashData(secret string, data []byte) [64]byte {
	h := hmac.New(sha512.New, []byte(secret))
	h.Write(data)

	m := h.Sum(nil)

	var mbuf [64]byte
	for i, _ := range mbuf {
		mbuf[i] = m[i]
	}

	return mbuf
}

// TODO: Should refactor this into minnow.go (or equivalent)
func readMessage(conn net.Conn, newMessages func(*minnow.Packet)) {
    for {
        res := new(minnow.PacketHeader)
        err := binary.Read(conn, binary.BigEndian, res)
        if err != nil {
			if err != io.EOF {
				log.Fatalf("Received error on header reader: %v\n", err)
			}
			newMessages(nil)
            break
        }

		d := make([]byte, res.Size)
		_, err = io.ReadFull(conn, d)
        if err != nil {
			if err != io.EOF {
				log.Fatalf("Received error on header reader: %v\n", err)
			}
			newMessages(nil)
            break
        }
        msg := minnow.Packet{Header: *res, Payload: d}
        newMessages(&msg)
    }
}

var peer = flag.String("peer", "0.0.0.0:9876", "gimme a host and port")

func printMessageChan() chan []byte{
	var c chan []byte = make(chan []byte)
	go func() {
		msg := ""
		for {
			v := <-c
			if v == nil {
				println(msg)
				msg = ""
			} else {
				msg += string(v)
			}
		}
	}()
	return c
}

func main() {
    flag.Parse()
    ln, err := net.Listen("tcp", *peer)
    if err != nil {
        log.Fatal("Error binding to socket: %+v", err)
    }
    log.Printf("Listening on: %s", *peer)
    for {
        conn, err := ln.Accept()
		messagePrinter := messageValidator("goduckyourself", printMessageChan())
        if err != nil {
            log.Print("Error opening connection: %+v", err)
            continue
        }

        go readMessage(conn, messagePrinter)
    }
}
