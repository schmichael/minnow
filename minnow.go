package minnow

type PacketHeader struct {
    SequenceN int32
    Mac [64]byte
    Size int32
}
