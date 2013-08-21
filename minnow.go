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

type FakePacketResult struct {
	Hasher  hash.Hash
	Message []byte
}

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
		numchaff:    1000, // FIXME: Randomize?
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
		numchans := mw.numchaff + 1
		packetchans := make([]chan *Packet, numchans)
		packetchans[0] = sequentialPacketChannel(mw.message, mw.hash)
		// Write chaff asynchronously
		for i := 1; i < numchans; i++ {
			// FIXME: Length should be randomized
			faker, err := fakeMessage(len(mw.message))
			if err != nil {
				return err
			}
			packetchans[i] = sequentialPacketChannel(faker.Message, faker.Hasher)
		}

		outpackets := randomPacketRouter(packetchans)

		// FIXME: Randomize the packets/order
		for p := range outpackets {
			err := mw.writePacket(p)
			if err != nil {
				return err
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

		outchan <- nil
	}()

	return outchan
}

// Create a mock hasher and buffer
func fakeMessage(packetSize int) (*FakePacketResult, error) {
	var err error

	payloadbuf := make([]byte, packetSize, packetSize)

	sz := uint64(0)
	for sz == 0 {
		sz = uint64(mathRand.Int63()) / 1000000000000000
	}
	hashseed := make([]byte, sz, sz)

	_, err = cryptoRand.Read(hashseed)
	if err != nil {
		return nil, err
	}

	h := hmac.New(sha512.New, hashseed)

	_, err = cryptoRand.Read(payloadbuf)
	if err != nil {
		return nil, err
	}

	return &FakePacketResult{h, payloadbuf}, nil
}

// Radomly select packets from the provided channels until they
// are all depleted (received a nil)
func randomPacketRouter(inchans []chan *Packet) chan *Packet {
	outchan := make(chan *Packet)
	go func() {
		for len(inchans) > 0 {
			ndx := mathRand.Intn(len(inchans))
			val := <-inchans[ndx]
			// This packet provider is done
			if val == nil {
				inchans = append(inchans[:ndx], inchans[ndx+1:]...)
			} else {
				outchan <- val
			}
		}
		close(outchan)
	}()

	return outchan
}
