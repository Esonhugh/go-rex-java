package model

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"

	"github.com/esonhugh/go-rex-java/constants"
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
	// Try to peek at the first byte to check if it's an opcode
	peekBuf := make([]byte, 1)
	n, err := reader.Read(peekBuf)
	if err != nil {
		return err
	}
	if n != 1 {
		return &DecodeError{Message: "failed to peek at first byte"}
	}

	// Debug: Track position for inline ClassDesc detection
	firstByte := peekBuf[0]
	debugLog("ClassDesc.Decode: Starting, first byte=0x%02x", firstByte)

	// Put the byte back
	reader = io.MultiReader(bytes.NewReader(peekBuf), reader)

	// Check if the first byte is a valid opcode for ClassDesc
	opcode := peekBuf[0]

	// Special handling for 0x00: it might be TC_NULL or the start of an inline ClassDesc (class name length)
	// If it's 0x00, peek at the next byte to check if it's also 0x00 (class name length = 0)
	isInlineClassDesc := false
	if opcode == 0x00 {
		// Read the next byte to check
		peekBuf2 := make([]byte, 1)
		n2, err2 := reader.Read(peekBuf2)
		if err2 == nil && n2 == 1 {
			// If next byte is also 0x00, it's likely an inline ClassDesc (class name length = 0x00 0x00)
			if peekBuf2[0] == 0x00 {
				// This is likely an inline ClassDesc with empty class name
				isInlineClassDesc = true
				debugLog("ClassDesc.Decode: Detected inline ClassDesc (0x00 0x00 as class name length)")
				// Put both bytes back in correct order
				reader = io.MultiReader(bytes.NewReader(peekBuf), bytes.NewReader(peekBuf2), reader)
			} else {
				// Second byte is not 0x00, so first 0x00 is likely TC_NULL
				// Put both bytes back
				reader = io.MultiReader(bytes.NewReader(peekBuf), bytes.NewReader(peekBuf2), reader)
			}
		} else {
			// Can't read second byte, assume it's TC_NULL
			// Put first byte back
			reader = io.MultiReader(bytes.NewReader(peekBuf), reader)
		}
	}

	isValidOpcode := !isInlineClassDesc && (opcode == constants.TC_NULL ||
		opcode == constants.TC_CLASSDESC ||
		opcode == constants.TC_REFERENCE ||
		opcode == constants.TC_PROXYCLASSDESC)

	if isValidOpcode && !isInlineClassDesc {
		// Use DecodeElement to decode the ClassDesc with opcode
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
	} else {
		// Inline ClassDesc (no opcode) - directly decode as NewClassDesc
		// This happens when ClassDesc is embedded directly without an opcode
		debugLog("ClassDesc.Decode: Detected inline ClassDesc (no opcode), first byte=0x%02x", opcode)
		newClassDesc := NewNewClassDesc(stream)
		if err := newClassDesc.Decode(reader, stream); err != nil {
			debugLog("ClassDesc.Decode: Failed to decode inline ClassDesc: %v", err)
			return err
		}
		cd.Description = newClassDesc
		cd.Stream = stream
		debugLog("ClassDesc.Decode: Decoded inline ClassDesc, OmitFlagsAndFields=%v, ClassAnnotation=%v",
			newClassDesc.OmitFlagsAndFields, newClassDesc.ClassAnnotation != nil)
		if newClassDesc.ClassAnnotation != nil {
			debugLog("ClassDesc.Decode: ClassAnnotation has %d elements", len(newClassDesc.ClassAnnotation.Contents))
		}
		return nil
	}
}

// Encode serializes the ClassDesc to bytes
func (cd *ClassDesc) Encode() ([]byte, error) {
	return cd.EncodeWithContext(nil)
}

// EncodeWithContext serializes the ClassDesc with a shared encode context
func (cd *ClassDesc) EncodeWithContext(ctx *EncodeContext) ([]byte, error) {
	if cd.Description == nil {
		return nil, &EncodeError{Message: "class description is nil"}
	}

	// Validate description type
	switch cd.Description.(type) {
	case *NullReference, *NewClassDesc, *Reference, *ProxyClassDesc:
		if ctx != nil {
			return EncodeElementWithContext(cd.Description, ctx)
		}
		return EncodeElement(cd.Description)
	default:
		return nil, &EncodeError{Message: fmt.Sprintf("failed to serialize ClassDesc: invalid type %T", cd.Description)}
	}
}

// marshalClassDesc marshals a ClassDesc to JSON-friendly format
func marshalClassDesc(cd *ClassDesc) interface{} {
	if cd == nil || cd.Description == nil {
		return nil
	}

	result := map[string]interface{}{
		"type":        "ClassDesc",
		"description": marshalElement(cd.Description),
	}
	return result
}

// MarshalJSON marshals ClassDesc to JSON
func (cd *ClassDesc) MarshalJSON() ([]byte, error) {
	return json.Marshal(marshalClassDesc(cd))
}

// String returns a string representation of the ClassDesc
func (cd *ClassDesc) String() string {
	if cd.Description == nil {
		return "ClassDesc(nil)"
	}
	return cd.Description.String()
}
