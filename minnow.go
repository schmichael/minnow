package minnow

import (
	"crypto/hmac"
	"crypto/sha512"
	"encoding/binary"
	"hash"
	"io"
)

type PacketHeader struct {
	SequenceN int32
	Mac       [64]byte
	Size      int32
}

type Packet struct {
	Header  PacketHeader
	Payload []byte
}

type Stream struct {
	w io.Writer
	h hash.Hash
}

func NewStream(w io.Writer, secret []byte) *Stream {
	return &Stream{w: w, h: hmac.New(sha512.New, secret)}
}

func (s *Stream) WritePacket(packet []byte, seqn int32) error {
	var mbuf [64]byte

	s.h.Write(packet)
	defer s.h.Reset()

	m := s.h.Sum(nil)

	for i, _ := range mbuf {
		mbuf[i] = m[i]
	}

	h := PacketHeader{
		SequenceN: seqn,
		Mac:       mbuf,
		Size:      int32(len(packet)),
	}

	err := binary.Write(s.w, binary.BigEndian, h)
	if err != nil {
		return err
	}

	_, err = s.w.Write(packet)
	if err != nil {
		return err
	}

	return nil
}
