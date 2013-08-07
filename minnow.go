package minnow

import (
	"crypto/hmac"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"hash"
	"io"
	"log"
	"sync"
	"time"

	cryptoRand "crypto/rand"
	mathRand "math/rand"
)

var ErrAlreadyClosed = errors.New("Writer has already been closed")
var ErrMaxLengthExceeded = errors.New("Maximum message length (1<<64 - 1) exceeded")

type Packet struct {
       Header  PacketHeader
       Payload []byte
}

type PacketHeader struct {
	SequenceN uint64
	Mac       [64]byte
	Size      uint64
}

type MessageWriteCloser struct {
	closed bool
	hash hash.Hash
	message []byte
	destination io.WriteCloser
	wg *sync.WaitGroup
}

func NewMessageWriteCloser(secret []byte, w io.WriteCloser) *MessageWriteCloser {
	return &MessageWriteCloser{
		closed: false,
		hash: hmac.New(sha512.New, secret),
		message: make([]byte, 0),
		destination: w,
		wg: new(sync.WaitGroup),
	}
}

// Writes a message fragment to the internal buffer
// Return value is always (len(m), nil)
func (mw *MessageWriteCloser) Write(m []byte) (int, error) {
	mw.message = append(mw.message, m...)
	return len(m), nil
}

// Close is when we actually get the end of the message and can write it
func (mw *MessageWriteCloser) Close() (error) {
	if !mw.closed {
		log.Printf("Writing message:\n%s", string(mw.message))
		mw.closed = true
		// Write chaff asynchronously
		mw.wg.Add(1)
		go binaryChaff(mw.destination, mw.wg.Done)

		// Write the real message
		_, err := mw.writeMessage()

		// Wait for chaff to finish writing before closing connection
		mw.wg.Wait()

		// Either close and handle error or just close
		if err != nil {
			// Always close the destination
			mw.destination.Close()
			return err
		}
		return mw.destination.Close()
	}
	return ErrAlreadyClosed
}

func (mw *MessageWriteCloser) writeMessage() (n int, err error) {
	log.Printf("Writing message <<%s>> len: %d cap: %d", string(mw.message), len(mw.message), cap(mw.message))
	for n, _ = range mw.message {
		_, err = mw.writePacket(uint64(n), mw.message[n:n + 1])
		log.Printf("Wrote seq %d: %v with err: %v", n, mw.message[n:n + 1], err)
		if err != nil {
			return
		}
		time.Sleep(time.Duration(mathRand.Intn(10)) * time.Millisecond)
	}
	return
}

func (mw *MessageWriteCloser) writePacket(seqn uint64, packet []byte) (int, error) {
	var mbuf [64]byte

	mw.hash.Write(packet)
	defer mw.hash.Reset()

	m := mw.hash.Sum(nil)

	for i, _ := range mbuf {
		mbuf[i] = m[i]
	}

	h := PacketHeader{
		SequenceN: seqn,
		Mac:       mbuf,
		Size:      uint64(len(packet)),
	}

	err := binary.Write(mw.destination, binary.BigEndian, h)
	if err != nil {
		return 0, err
	}

	n, err := mw.destination.Write(packet)
	if err != nil {
		return n, err
	}

	return len(packet), nil
}

func binaryChaff(w io.Writer, done func()) {
	defer done()

	var err error
	ph := &PacketHeader{Size: 1}
	macbuf := make([]byte, 64, 64)
	payloadbuf := make([]byte, 1, 1)
	sz := uint64(0)
	for sz == 0 {
		//FIXME Need to base amount of chaff of message size without
		//      hinting at message size
		sz = uint64(mathRand.Int63()) / 1000000000000000
	}

	log.Printf("Writing %d chaff packets", sz)

	for ; ph.SequenceN < sz; ph.SequenceN++ {
		_, err = cryptoRand.Read(macbuf)
		if err != nil {
			return
		}

		for i, _ := range macbuf {
			ph.Mac[i] = macbuf[i]
		}

		err = binary.Write(w, binary.BigEndian, ph)
		if err != nil {
			log.Printf("Failed to write chaff header: %s", err)
			return
		}

		_, err = cryptoRand.Read(payloadbuf)
		if err != nil {
			return
		}

		_, err = w.Write(payloadbuf)
		if err != nil {
			return
		}
		time.Sleep(time.Duration(mathRand.Intn(2)) * time.Millisecond)
	}
	log.Printf("Wrote %d chaff packets", ph.SequenceN)

}
