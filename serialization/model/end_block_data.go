package model

import (
	"io"
)

// EndBlockData represents end of block data in Java serialization
type EndBlockData struct {
	*BaseElement
}

// NewEndBlockData creates a new EndBlockData instance
func NewEndBlockData(stream *Stream) *EndBlockData {
	return &EndBlockData{
		BaseElement: NewBaseElement(stream),
	}
}

// Decode deserializes an EndBlockData from the given reader
func (ebd *EndBlockData) Decode(reader io.Reader, stream *Stream) error {
	ebd.Stream = stream
	return nil
}

// Encode serializes the EndBlockData to bytes
func (ebd *EndBlockData) Encode() ([]byte, error) {
	return []byte{}, nil
}

// String returns a string representation of the EndBlockData
func (ebd *EndBlockData) String() string {
	return "EndBlockData"
}

// marshalEndBlockData marshals an EndBlockData to JSON-friendly format
func marshalEndBlockData() interface{} {
	return map[string]interface{}{
		"type": "EndBlockData",
	}
}
