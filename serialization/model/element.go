package model

import (
	"github.com/esonhugh/go-rex-java/constants"
	"io"
)

// Element represents the base interface for all serialization elements
type Element interface {
	// Decode deserializes the element from the given reader
	Decode(reader io.Reader, stream *Stream) error
	// Encode serializes the element to bytes
	Encode() ([]byte, error)
	// String returns a string representation of the element
	String() string
}

// BaseElement provides common functionality for all elements
type BaseElement struct {
	Stream *Stream
}

// NewBaseElement creates a new BaseElement
func NewBaseElement(stream *Stream) *BaseElement {
	return &BaseElement{Stream: stream}
}

// Decode is the default implementation for elements
func (e *BaseElement) Decode(reader io.Reader, stream *Stream) error {
	return nil
}

// Encode is the default implementation for elements
func (e *BaseElement) Encode() ([]byte, error) {
	return []byte{}, nil
}

// String returns the class name as string representation
func (e *BaseElement) String() string {
	return "Element"
}

// DecodeElement is a helper function to decode any element type
func DecodeElement(reader io.Reader, stream *Stream) (Element, error) {
	opcode := make([]byte, 1)
	_, err := reader.Read(opcode)
	if err != nil {
		// Return the original error (including io.EOF)
		return nil, err
	}

	switch opcode[0] {
	case constants.TC_BLOCKDATA:
		elem := NewBlockData(stream)
		err := elem.Decode(reader, stream)
		return elem, err
	case constants.TC_BLOCKDATALONG:
		elem := NewBlockDataLong(stream)
		err := elem.Decode(reader, stream)
		return elem, err
	case constants.TC_ENDBLOCKDATA:
		elem := NewEndBlockData(stream)
		err := elem.Decode(reader, stream)
		return elem, err
	case constants.TC_OBJECT:
		elem := NewNewObject(stream)
		err := elem.Decode(reader, stream)
		return elem, err
	case constants.TC_CLASS:
		elem := NewNewClass(stream)
		err := elem.Decode(reader, stream)
		return elem, err
	case constants.TC_ARRAY:
		elem := NewNewArray(stream)
		err := elem.Decode(reader, stream)
		return elem, err
	case constants.TC_STRING:
		elem := NewUtf(stream, "")
		err := elem.Decode(reader, stream)
		if err == nil && stream != nil {
			stream.AddReference(elem)
		}
		return elem, err
	case constants.TC_LONGSTRING:
		elem := NewLongUtf(stream)
		err := elem.Decode(reader, stream)
		if err == nil && stream != nil {
			stream.AddReference(elem)
		}
		return elem, err
	case constants.TC_ENUM:
		elem := NewNewEnum(stream)
		err := elem.Decode(reader, stream)
		return elem, err
	case constants.TC_CLASSDESC:
		elem := NewNewClassDesc(stream)
		err := elem.Decode(reader, stream)
		return elem, err
	case constants.TC_PROXYCLASSDESC:
		elem := NewProxyClassDesc(stream)
		err := elem.Decode(reader, stream)
		return elem, err
	case constants.TC_REFERENCE:
		elem := NewReference(stream, 0)
		err := elem.Decode(reader, stream)
		return elem, err
	case constants.TC_NULL:
		elem := NewNullReference(stream)
		err := elem.Decode(reader, stream)
		return elem, err
	case constants.TC_EXCEPTION:
		return nil, &DecodeError{Message: "failed to unserialize unsupported TC_EXCEPTION content"}
	case constants.TC_RESET:
		elem := NewReset(stream)
		err := elem.Decode(reader, stream)
		return elem, err
	default:
		return nil, &DecodeError{Message: "failed to unserialize content"}
	}
}

// EncodeElement is a helper function to encode any element type
func EncodeElement(element Element) ([]byte, error) {
	var opcode byte

	switch element.(type) {
	case *BlockData:
		opcode = constants.TC_BLOCKDATA
	case *BlockDataLong:
		opcode = constants.TC_BLOCKDATALONG
	case *EndBlockData:
		opcode = constants.TC_ENDBLOCKDATA
	case *NewObject:
		opcode = constants.TC_OBJECT
	case *NewClass:
		opcode = constants.TC_CLASS
	case *NewArray:
		opcode = constants.TC_ARRAY
	case *Utf:
		opcode = constants.TC_STRING
	case *LongUtf:
		opcode = constants.TC_LONGSTRING
	case *NewEnum:
		opcode = constants.TC_ENUM
	case *NewClassDesc:
		opcode = constants.TC_CLASSDESC
	case *ProxyClassDesc:
		opcode = constants.TC_PROXYCLASSDESC
	case *NullReference:
		opcode = constants.TC_NULL
	case *Reset:
		opcode = constants.TC_RESET
	case *Reference:
		opcode = 0x71 // TC_REFERENCE
	default:
		return nil, &EncodeError{Message: "failed to serialize content"}
	}

	encoded, err := element.Encode()
	if err != nil {
		return nil, err
	}

	result := make([]byte, 1+len(encoded))
	result[0] = opcode
	copy(result[1:], encoded)
	return result, nil
}

// DecodeError represents an error during deserialization
type DecodeError struct {
	Message string
}

func (e *DecodeError) Error() string {
	return e.Message
}

// EncodeError represents an error during serialization
type EncodeError struct {
	Message string
}

func (e *EncodeError) Error() string {
	return e.Message
}
