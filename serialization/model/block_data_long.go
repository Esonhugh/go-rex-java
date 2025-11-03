package model

import (
	"encoding/binary"
	"fmt"
	"github.com/esonhugh/go-rex-java/constants"
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

	// Read length (4 bytes, uint32)
	lengthBytes := make([]byte, constants.SIZE_INT)
    if _, err := io.ReadFull(reader, lengthBytes); err != nil {
        if err == io.EOF || err == io.ErrUnexpectedEOF {
            return nil
        }
        return &DecodeError{Message: "failed to read long block data length"}
    }
	length := binary.BigEndian.Uint32(lengthBytes)

	// Read data
	if length == 0 {
		bdl.Data = make([]byte, 0)
	} else {
		bdl.Data = make([]byte, length)
		if _, err := io.ReadFull(reader, bdl.Data); err != nil {
			if err == io.EOF || err == io.ErrUnexpectedEOF {
				// Use partial data if available
				if len(bdl.Data) > 0 {
					// Keep partial data
				} else {
					bdl.Data = make([]byte, 0)
				}
				return nil
			}
			return &DecodeError{Message: "failed to read long block data contents"}
		}
	}

	return nil
}

// Encode serializes the BlockDataLong to bytes
func (bdl *BlockDataLong) Encode() ([]byte, error) {
	encoded := make([]byte, 0, 4+len(bdl.Data))

	// Encode length (4 bytes, uint32)
	lengthBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(lengthBytes, uint32(len(bdl.Data)))
	encoded = append(encoded, lengthBytes...)

	// Encode data
	if len(bdl.Data) > 0 {
		encoded = append(encoded, bdl.Data...)
	}

	return encoded, nil
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
