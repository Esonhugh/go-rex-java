package model

import (
	"fmt"
	"github.com/esonhugh/go-rex-java/constants"
)

// EncodeContext tracks elements that have been encoded during encoding process
// This is needed to use TC_REFERENCE for elements that appear multiple times
type EncodeContext struct {
	// encodedElements maps element to its handle (index in references)
	// We use pointer addresses as keys for exact matching
	encodedElements map[Element]int
	// stream references (from decode phase)
	streamReferences []Element
	// nextHandle tracks the next available handle index for new elements
	nextHandle int
}

// NewEncodeContext creates a new encode context
func NewEncodeContext(stream *Stream) *EncodeContext {
	ctx := &EncodeContext{
		encodedElements:  make(map[Element]int),
		streamReferences: nil,
		nextHandle:       0,
	}

	if stream != nil {
		ctx.streamReferences = stream.References
		ctx.nextHandle = len(stream.References)
	}

	return ctx
}

// registerElement registers an element with the encode context
// assigning a handle that matches the original reference index when possible
func (ctx *EncodeContext) registerElement(element Element) {
	if ctx == nil || !ShouldBeReferenced(element) {
		return
	}

	if _, exists := ctx.encodedElements[element]; exists {
		return
	}

	if ctx.streamReferences != nil {
		if idx := findReferenceIndexByContent(element, ctx.streamReferences); idx >= 0 {
			ctx.encodedElements[element] = idx
			return
		}
	}

	handle := ctx.nextHandle
	ctx.encodedElements[element] = handle
	ctx.nextHandle++
}

// EncodeElementWithContext encodes an element, checking both:
// 1. If element is in stream's references (from decode)
// 2. If element has been encoded in this encoding session
func EncodeElementWithContext(element Element, ctx *EncodeContext) ([]byte, error) {
	if element == nil {
		return nil, &EncodeError{Message: "element is nil"}
	}

	if ctx != nil {
		if handle, exists := ctx.encodedElements[element]; exists {
			handleValue := uint32(handle) + constants.BASE_WIRE_HANDLE
			refElem := NewReference(nil, handleValue)
			return EncodeElement(refElem)
		}
	}

	// Element is new, encode it normally
	// Determine opcode first
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
		opcode = constants.TC_REFERENCE
	default:
		return nil, &EncodeError{Message: fmt.Sprintf("failed to serialize content: unknown type %T", element)}
	}

	// Encode element body (without opcode)
	var encoded []byte
	var err error
	switch e := element.(type) {
	case *NewObject:
		encoded, err = e.EncodeWithContext(ctx)
	case *NewArray:
		encoded, err = e.EncodeWithContext(ctx)
	case *NewClassDesc:
		encoded, err = e.EncodeWithContext(ctx)
	case *Annotation:
		encoded, err = e.EncodeWithContext(ctx)
	default:
		encoded, err = element.Encode()
	}

	if err != nil {
		return nil, err
	}

	// Combine opcode and encoded body
	result := make([]byte, 1+len(encoded))
	result[0] = opcode
	copy(result[1:], encoded)

	// Add to encoded elements if it should be referenced
	if ctx != nil {
		ctx.registerElement(element)
	}

	return result, nil
}
