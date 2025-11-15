package model

import (
	"fmt"
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
	elementIndex := 0
	debugLog("Annotation.Decode: Starting to decode annotation")
	for {
		element, err := DecodeElement(reader, stream)
		if err != nil {
			debugLog("Annotation.Decode: Failed to decode element at index %d: %v", elementIndex, err)
			return err
		}
		// Debug: Log element being decoded
		elementType := fmt.Sprintf("%T", element)
		if bd, ok := element.(*BlockData); ok {
			debugLog("Annotation.Decode: ✅ Decoded BlockData at index %d, length=%d, data=%x", elementIndex, len(bd.Data), bd.Data[:min(len(bd.Data), 8)])
		} else {
			debugLog("Annotation.Decode: Decoded element at index %d, type=%s", elementIndex, elementType)
		}
		a.Contents = append(a.Contents, element)
		if _, ok := element.(*EndBlockData); ok {
			debugLog("Annotation.Decode: Found EndBlockData at index %d, stopping. Total elements: %d", elementIndex, len(a.Contents))
			break
		}
		elementIndex++
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
	for i, element := range a.Contents {
		// Use EncodeElementWithContext to check if element should use TC_REFERENCE
		var elementBytes []byte
		var err error
		if ctx != nil {
			elementBytes, err = EncodeElementWithContext(element, ctx)
		} else {
			elementBytes, err = EncodeElementWithReferences(element, a.Stream)
		}
		if err != nil {
			return nil, err
		}
		// Debug: Log Annotation encoding
		elementType := fmt.Sprintf("%T", element)
		debugLog("Annotation.EncodeWithContext: Encoding element at index %d, type=%s, encoded bytes=%d", i, elementType, len(elementBytes))
		if bd, ok := element.(*BlockData); ok {
			debugLog("Annotation.EncodeWithContext: BlockData length=%d, encoded bytes=%d, first byte=0x%02x", len(bd.Data), len(elementBytes), elementBytes[0])
			if len(elementBytes) > 0 && elementBytes[0] != 0x77 {
				debugLog("⚠️  Annotation.EncodeWithContext: BlockData opcode is 0x%02x, expected 0x77!", elementBytes[0])
			}
		}
		encoded = append(encoded, elementBytes...)
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
