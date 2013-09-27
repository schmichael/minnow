package minnow

import (
	"crypto/hmac"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"hash"
	"io"
	"log"

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
	closed      bool
	hash        hash.Hash
	message     []byte
	destination io.WriteCloser
	numchaff    int
}

func NewMessageWriteCloser(secret []byte, w io.WriteCloser) *MessageWriteCloser {
	return &MessageWriteCloser{
		closed:      false,
		hash:        hmac.New(sha512.New, secret),
		message:     make([]byte, 0),
		destination: w,
		numchaff:    200, // FIXME: Randomize?
	}
}

// Writes a message fragment to the internal buffer
// Return value is always (len(m), nil)
func (mw *MessageWriteCloser) Write(m []byte) (int, error) {
	mw.message = append(mw.message, m...)
	return len(m), nil
}

// Close is when we actually get the end of the message and can write it
func (mw *MessageWriteCloser) Close() error {
	if !mw.closed {
		defer mw.destination.Close()
		log.Printf("Writing message:\n%s", string(mw.message))

		mw.closed = true

		for p := range sequentialPacketChannel(mw.message, mw.hash) {
			packets := make([]Packet, mw.numchaff+1)
			packets[0] = *p
			for i := 1; i < mw.numchaff+1; i++ {
				packets[i] = makeFakeMessage(1, p.Header.SequenceN)
			}

			packets = randomizePackets(packets)

			for _, p := range packets {
				mw.writePacket(&p)
			}
		}
		return mw.destination.Close()
	}
	return ErrAlreadyClosed
}

func (mw *MessageWriteCloser) writePacket(packet *Packet) error {
	log.Printf("Writing packet: #%d - %+v\n", packet.Header.SequenceN, packet.Payload)
	err := binary.Write(mw.destination, binary.BigEndian, packet.Header)
	if err != nil {
		return err
	}

	_, err = mw.destination.Write(packet.Payload)
	if err != nil {
		return err
	}

	return nil
}

type MessageReader struct {
	hash    hash.Hash
	message []byte
	reader  io.Reader
	closed  bool
}

func NewMessageReader(secret []byte, r io.Reader) *MessageReader {
	return &MessageReader{
		hash:    hmac.New(sha512.New, secret),
		message: make([]byte, 0),
		reader:  r,
		closed:  false,
	}
}

func (r *MessageReader) ReadAll() []byte {
	for {
		res := new(PacketHeader)
		err := binary.Read(r.reader, binary.BigEndian, res)
		if err != nil {
			if err != io.EOF {
				// Probably shouldn't Fatal on this...
				log.Fatalf("Received an error reading header: %w\n", err)
			}
			r.closed = true
			break
		}

		d := make([]byte, res.Size)
		_, err = io.ReadFull(r.reader, d)
		if err != nil {
			if err != io.EOF {
				log.Fatalf("Received error reading message body: %w\n", err)
			}
			r.closed = true
			break
		}
		if r.matches(d, res.Mac) {
			r.message = append(r.message, d...)
		}
	}
	return r.message
}

func (r *MessageReader) matches(data []byte, provided [64]byte) bool {
	r.hash.Write(data)
	defer r.hash.Reset()

	m := r.hash.Sum(nil)

	var mbuf [64]byte
	for i, _ := range mbuf {
		mbuf[i] = m[i]
	}

	return mbuf == provided
}

// Send len(data) # of sequential packets, hashed with the provided hash.Hash
// down the provided channel
func sequentialPacketChannel(data []byte, hasher hash.Hash) chan *Packet {
	// FIXME: Packet size is hard-coded at 1
	outchan := make(chan *Packet)
	go func() {
		for i, _ := range data {
			var mbuf [64]byte

			hasher.Write(data[i : i+1])
			m := hasher.Sum(nil)
			for i, _ := range mbuf {
				mbuf[i] = m[i]
			}
			hasher.Reset()

			h := PacketHeader{
				SequenceN: uint64(i),
				Mac:       mbuf,
				Size:      uint64(1),
			}
			outchan <- &Packet{h, data[i : i+1]}
		}

		close(outchan)
	}()

	return outchan
}

func randomizePackets(packets []Packet) []Packet {
	newpackets := make([]Packet, 0)

	for len(packets) > 0 {
		randndx := mathRand.Intn(len(packets))
		newpackets = append(newpackets, packets[randndx])
		packets = append(packets[:randndx], packets[randndx+1:]...)
	}

	return newpackets
}

func makeFakeMessage(size uint64, sequencenum uint64) Packet {
	crypthash := make([]byte, 64)
	hash := new([64]byte)
	payloadbuf := make([]byte, size)

	cryptoRand.Read(payloadbuf)
	cryptoRand.Read(crypthash)

	for i, v := range crypthash {
		hash[i] = v
	}

	ph := PacketHeader{
		SequenceN: sequencenum,
		Mac:       *hash,
		Size:      size,
	}

	return Packet{ph, payloadbuf}
}
