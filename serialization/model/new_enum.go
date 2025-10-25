package model

import (
	"io"
)

// NewEnum represents a new enum in Java serialization
type NewEnum struct {
	*BaseElement
	EnumClassDesc    *ClassDesc
	EnumConstantName *Utf
}

// NewNewEnum creates a new NewEnum instance
func NewNewEnum(stream *Stream) *NewEnum {
	return &NewEnum{
		BaseElement:      NewBaseElement(stream),
		EnumClassDesc:    nil,
		EnumConstantName: nil,
	}
}

// Decode deserializes a NewEnum from the given reader
func (ne *NewEnum) Decode(reader io.Reader, stream *Stream) error {
	ne.Stream = stream
	// TODO: Implement new enum decoding
	return nil
}

// Encode serializes the NewEnum to bytes
func (ne *NewEnum) Encode() ([]byte, error) {
	// TODO: Implement new enum encoding
	return []byte{}, nil
}

// String returns a string representation of the NewEnum
func (ne *NewEnum) String() string {
	return "NewEnum"
}
