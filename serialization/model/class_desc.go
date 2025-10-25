package model

import (
	"io"
)

// ClassDesc represents a class description in Java serialization
type ClassDesc struct {
	*BaseElement
	Description Element
}

// NewClassDesc creates a new ClassDesc instance
func NewClassDescInstance(stream *Stream) *ClassDesc {
	return &ClassDesc{
		BaseElement: NewBaseElement(stream),
		Description: nil,
	}
}

// Decode deserializes a ClassDesc from the given reader
func (cd *ClassDesc) Decode(reader io.Reader, stream *Stream) error {
	content, err := DecodeElement(reader, stream)
	if err != nil {
		return err
	}

	// Validate content type
	switch content.(type) {
	case *NullReference, *NewClassDesc, *Reference, *ProxyClassDesc:
		cd.Description = content
		cd.Stream = stream
		return nil
	default:
		return &DecodeError{Message: "ClassDesc unserialize failed"}
	}
}

// Encode serializes the ClassDesc to bytes
func (cd *ClassDesc) Encode() ([]byte, error) {
	if cd.Description == nil {
		return nil, &EncodeError{Message: "class description is nil"}
	}

	// Validate description type
	switch cd.Description.(type) {
	case *NullReference, *NewClassDesc, *Reference, *ProxyClassDesc:
		return EncodeElement(cd.Description)
	default:
		return nil, &EncodeError{Message: "failed to serialize ClassDesc"}
	}
}

// String returns a string representation of the ClassDesc
func (cd *ClassDesc) String() string {
	if cd.Description == nil {
		return "ClassDesc(nil)"
	}
	return cd.Description.String()
}
