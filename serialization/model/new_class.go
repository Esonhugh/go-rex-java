package model

import (
	"io"
)

// NewClass represents a new class in Java serialization
type NewClass struct {
	*BaseElement
	ClassName *Utf
}

// NewNewClass creates a new NewClass instance
func NewNewClass(stream *Stream) *NewClass {
	return &NewClass{
		BaseElement: NewBaseElement(stream),
		ClassName:   nil,
	}
}

// Decode deserializes a NewClass from the given reader
func (nc *NewClass) Decode(reader io.Reader, stream *Stream) error {
	nc.Stream = stream
	// TODO: Implement new class decoding
	return nil
}

// Encode serializes the NewClass to bytes
func (nc *NewClass) Encode() ([]byte, error) {
	// TODO: Implement new class encoding
	return []byte{}, nil
}

// String returns a string representation of the NewClass
func (nc *NewClass) String() string {
	return "NewClass"
}

// marshalNewClass marshals a NewClass to JSON-friendly format
func marshalNewClass(nc *NewClass) interface{} {
	if nc == nil {
		return nil
	}
	return map[string]interface{}{
		"type":       "NewClass",
		"class_name": marshalUtf(nc.ClassName),
	}
}
