package model

import (
	"encoding/binary"
	"io"
)

// Reference represents an object reference in Java serialization
type Reference struct {
	*BaseElement
	Handle uint32
}

// NewReference creates a new Reference instance
func NewReference(stream *Stream, handle uint32) *Reference {
	return &Reference{
		BaseElement: NewBaseElement(stream),
		Handle:      handle,
	}
}

// Decode deserializes a Reference from the given reader
func (r *Reference) Decode(reader io.Reader, stream *Stream) error {
	handleBytes := make([]byte, 4)
	n, err := reader.Read(handleBytes)
	if err != nil || n != 4 {
		return &DecodeError{Message: "failed to read reference handle"}
	}

	r.Handle = binary.BigEndian.Uint32(handleBytes)
	r.Stream = stream
	return nil
}

// Encode serializes the Reference to bytes
func (r *Reference) Encode() ([]byte, error) {
	encoded := make([]byte, 4)
	binary.BigEndian.PutUint32(encoded, r.Handle)
	return encoded, nil
}

// String returns a string representation of the Reference
func (r *Reference) String() string {
	return "Reference"
}
