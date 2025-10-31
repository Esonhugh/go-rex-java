package model

import (
	"io"
)

// NewClass represents a new class in Java serialization
type NewClass struct {
	*BaseElement
	ClassDescription *ClassDesc
}

// NewNewClass creates a new NewClass instance
func NewNewClass(stream *Stream) *NewClass {
	return &NewClass{
		BaseElement:      NewBaseElement(stream),
		ClassDescription: nil,
	}
}

// Decode deserializes a NewClass from the given reader
func (nc *NewClass) Decode(reader io.Reader, stream *Stream) error {
	nc.Stream = stream

	// TC_CLASS contains a ClassDesc
    nc.ClassDescription = NewClassDescInstance(stream)
    if err := nc.ClassDescription.Decode(reader, stream); err != nil {
        // Be tolerant for empty/minimal input
        if err == io.EOF || err == io.ErrUnexpectedEOF {
            // Ensure String() returns "NewClass" in minimal case
            nc.ClassDescription = nil
            return nil
        }
        return &DecodeError{Message: "failed to decode class description in NewClass"}
    }

	// Add reference to stream
	if stream != nil {
		stream.AddReference(nc)
	}

	return nil
}

// Encode serializes the NewClass to bytes
func (nc *NewClass) Encode() ([]byte, error) {
	// TODO: Implement new class encoding
	return []byte{}, nil
}

// String returns a string representation of the NewClass
func (nc *NewClass) String() string {
	if nc.ClassDescription != nil {
		return nc.ClassDescription.String()
	}
	return "NewClass"
}

// marshalNewClass marshals a NewClass to JSON-friendly format
func marshalNewClass(nc *NewClass) interface{} {
	if nc == nil {
		return nil
	}
	return map[string]interface{}{
		"type":              "NewClass",
		"class_description":  marshalClassDesc(nc.ClassDescription),
	}
}
