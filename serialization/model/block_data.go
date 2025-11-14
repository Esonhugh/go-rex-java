package model

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/esonhugh/go-rex-java/constants"
)

// BlockData represents block data in Java serialization
type BlockData struct {
	*BaseElement
	Data []byte
}

// NewBlockData creates a new BlockData instance
func NewBlockData(stream *Stream) *BlockData {
	return &BlockData{
		BaseElement: NewBaseElement(stream),
		Data:        make([]byte, 0),
	}
}

// Decode deserializes a BlockData from the given reader
func (bd *BlockData) Decode(reader io.Reader, stream *Stream) error {
	bd.Stream = stream

	// Read length (1 byte)
	lengthBytes := make([]byte, constants.SIZE_BYTE)
	if _, err := io.ReadFull(reader, lengthBytes); err != nil {
		return &DecodeError{Message: "failed to read block data length"}
	}
	length := lengthBytes[0]

	// Read data
	if length == 0 {
		bd.Data = make([]byte, 0)
	} else {
		bd.Data = make([]byte, length)
		if _, err := io.ReadFull(reader, bd.Data); err != nil {
			return &DecodeError{Message: "failed to read block data contents"}
		}
	}

	return nil
}

// Encode serializes the BlockData to bytes
func (bd *BlockData) Encode() ([]byte, error) {
	encoded := make([]byte, 1+len(bd.Data))
	encoded[0] = byte(len(bd.Data))
	copy(encoded[1:], bd.Data)
	// Debug: Log BlockData encoding
	showLen := len(bd.Data)
	if showLen > 16 {
		showLen = 16
	}
	if len(bd.Data) > 0 {
		debugLog("BlockData.Encode: length=%d, data=%x", len(bd.Data), bd.Data[:showLen])
	} else {
		debugLog("BlockData.Encode: length=0 (empty)")
	}
	return encoded, nil
}

// EncodeWithContext serializes the BlockData with a shared encode context
func (bd *BlockData) EncodeWithContext(ctx *EncodeContext) ([]byte, error) {
	// BlockData encoding is the same with or without context
	return bd.Encode()
}

// String returns a string representation of the BlockData
func (bd *BlockData) String() string {
	if len(bd.Data) == 0 {
		return "[ ]"
	}
	result := "[ "
	for i, b := range bd.Data {
		if i > 0 {
			result += ", "
		}
		result += fmt.Sprintf("0x%x", b)
	}
	result += " ]"
	return result
}

// marshalBlockData marshals a BlockData to JSON-friendly format
func marshalBlockData(bd *BlockData) interface{} {
	if bd == nil {
		return nil
	}

	// Convert bytes to hex strings for better JSON readability
	hexData := make([]string, len(bd.Data))
	for i, b := range bd.Data {
		hexData[i] = fmt.Sprintf("0x%02x", b)
	}

	return map[string]interface{}{
		"type": "BlockData",
		"data": hexData,
	}
}

// MarshalJSON marshals BlockData to JSON
func (bd *BlockData) MarshalJSON() ([]byte, error) {
	return json.Marshal(marshalBlockData(bd))
}
