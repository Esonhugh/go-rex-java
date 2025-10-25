package model

import (
	"io"
)

// NullReference represents a null reference in Java serialization
type NullReference struct {
	*BaseElement
}

// NewNullReference creates a new NullReference instance
func NewNullReference(stream *Stream) *NullReference {
	return &NullReference{
		BaseElement: NewBaseElement(stream),
	}
}

// Decode deserializes a NullReference from the given reader
func (nr *NullReference) Decode(reader io.Reader, stream *Stream) error {
	nr.Stream = stream
	return nil
}

// Encode serializes the NullReference to bytes
func (nr *NullReference) Encode() ([]byte, error) {
	return []byte{}, nil
}

// String returns a string representation of the NullReference
func (nr *NullReference) String() string {
	return "NullReference"
}
