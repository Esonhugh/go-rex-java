package model

import (
	"io"
)

// Annotation represents an annotation in Java serialization
type Annotation struct {
	*BaseElement
	Contents []Element
}

// NewAnnotation creates a new Annotation instance
func NewAnnotation(stream *Stream) *Annotation {
	return &Annotation{
		BaseElement: NewBaseElement(stream),
		Contents:    make([]Element, 0),
	}
}

// Decode deserializes an Annotation from the given reader
func (a *Annotation) Decode(reader io.Reader, stream *Stream) error {
	a.Stream = stream
	// Loop until we encounter EndBlockData
	for {
		element, err := DecodeElement(reader, stream)
		if err != nil {
			return err
		}
		a.Contents = append(a.Contents, element)
		if _, ok := element.(*EndBlockData); ok {
			break
		}
	}
	return nil
}

// Encode serializes the Annotation to bytes
func (a *Annotation) Encode() ([]byte, error) {
	encoded := make([]byte, 0, 1024)

	// Encode all contents
	for _, element := range a.Contents {
		elementBytes, err := EncodeElement(element)
		if err != nil {
			return nil, err
		}
		encoded = append(encoded, elementBytes...)
	}

	return encoded, nil
}

// String returns a string representation of the Annotation
func (a *Annotation) String() string {
	return "Annotation"
}
