package model

import (
	"io"
)

// NewArray represents a new array in Java serialization
type NewArray struct {
	*BaseElement
	ArrayDescription *ClassDesc
	Type             string
	Values           []interface{}
}

// NewNewArray creates a new NewArray instance
func NewNewArray(stream *Stream) *NewArray {
	return &NewArray{
		BaseElement:      NewBaseElement(stream),
		ArrayDescription: nil,
		Type:             "",
		Values:           make([]interface{}, 0),
	}
}

// Decode deserializes a NewArray from the given reader
func (na *NewArray) Decode(reader io.Reader, stream *Stream) error {
	na.Stream = stream
	// TODO: Implement new array decoding
	return nil
}

// Encode serializes the NewArray to bytes
func (na *NewArray) Encode() ([]byte, error) {
	// TODO: Implement new array encoding
	return []byte{}, nil
}

// String returns a string representation of the NewArray
func (na *NewArray) String() string {
	return "NewArray"
}

// marshalNewArray marshals a NewArray to JSON-friendly format
func marshalNewArray(na *NewArray) interface{} {
	if na == nil {
		return nil
	}
	return map[string]interface{}{
		"type":              "NewArray",
		"array_description": marshalClassDesc(na.ArrayDescription),
		"type_info":         na.Type,
		"values":            na.Values,
	}
}
