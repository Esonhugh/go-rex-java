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
	return a.EncodeWithContext(nil)
}

// EncodeWithContext serializes the Annotation with a shared encode context
func (a *Annotation) EncodeWithContext(ctx *EncodeContext) ([]byte, error) {
	encoded := make([]byte, 0, 1024)

	// Encode all contents
	for _, element := range a.Contents {
		// Use EncodeElementWithContext to check if element should use TC_REFERENCE
		if ctx != nil {
			elementBytes, err := EncodeElementWithContext(element, ctx)
			if err != nil {
				return nil, err
			}
			encoded = append(encoded, elementBytes...)
		} else {
			elementBytes, err := EncodeElementWithReferences(element, a.Stream)
			if err != nil {
				return nil, err
			}
			encoded = append(encoded, elementBytes...)
		}
	}

	return encoded, nil
}

// String returns a string representation of the Annotation
func (a *Annotation) String() string {
	return "Annotation"
}

// marshalAnnotation marshals an Annotation to JSON-friendly format
func marshalAnnotation(a *Annotation) interface{} {
	if a == nil {
		return nil
	}
	return map[string]interface{}{
		"type":     "Annotation",
		"contents": marshalElements(a.Contents),
	}
}
