package model

import (
	"io"
)

// Reset represents a reset marker in Java serialization
type Reset struct {
	*BaseElement
}

// NewReset creates a new Reset instance
func NewReset(stream *Stream) *Reset {
	return &Reset{
		BaseElement: NewBaseElement(stream),
	}
}

// Decode deserializes a Reset from the given reader
func (r *Reset) Decode(reader io.Reader, stream *Stream) error {
	r.Stream = stream
	return nil
}

// Encode serializes the Reset to bytes
func (r *Reset) Encode() ([]byte, error) {
	return []byte{}, nil
}

// String returns a string representation of the Reset
func (r *Reset) String() string {
	return "Reset"
}
