package model

import (
	"fmt"
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

// marshalBlockDataLong marshals a BlockDataLong to JSON-friendly format
func marshalBlockDataLong(bdl *BlockDataLong) interface{} {
	if bdl == nil {
		return nil
	}

	// Convert bytes to hex strings for better JSON readability
	hexData := make([]string, len(bdl.Data))
	for i, b := range bdl.Data {
		hexData[i] = fmt.Sprintf("0x%02x", b)
	}

	return map[string]interface{}{
		"type": "BlockDataLong",
		"data": hexData,
	}
}
