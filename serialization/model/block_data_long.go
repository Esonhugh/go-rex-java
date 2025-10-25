package model

import (
	"io"
)

// BlockDataLong represents long block data in Java serialization
type BlockDataLong struct {
	*BaseElement
	Data []byte
}

// NewBlockDataLong creates a new BlockDataLong instance
func NewBlockDataLong(stream *Stream) *BlockDataLong {
	return &BlockDataLong{
		BaseElement: NewBaseElement(stream),
		Data:        make([]byte, 0),
	}
}

// Decode deserializes a BlockDataLong from the given reader
func (bdl *BlockDataLong) Decode(reader io.Reader, stream *Stream) error {
	bdl.Stream = stream
	// TODO: Implement long block data decoding
	return nil
}

// Encode serializes the BlockDataLong to bytes
func (bdl *BlockDataLong) Encode() ([]byte, error) {
	// TODO: Implement long block data encoding
	return bdl.Data, nil
}

// String returns a string representation of the BlockDataLong
func (bdl *BlockDataLong) String() string {
	return "BlockDataLong"
}
