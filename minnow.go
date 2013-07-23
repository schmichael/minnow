package minnow

type PacketHeader struct {
    StreamId int32
    SequenceN int32
    Mac [64]byte
    Size int32
}
