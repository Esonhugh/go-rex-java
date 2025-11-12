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
	// encodedOnceHandle tracks whether a handle has already been emitted in this encode session
	encodedOnceHandle map[int]bool
	// stream references (from decode phase)
	streamReferences []Element
	// nextHandle tracks the next available handle index for new elements
	nextHandle int
}

// NewEncodeContext creates a new encode context
func NewEncodeContext(stream *Stream) *EncodeContext {
	ctx := &EncodeContext{
		encodedElements:   make(map[Element]int),
		encodedOnceHandle: make(map[int]bool),
		streamReferences:  stream.References,
		nextHandle:        0,
	}

	if stream != nil {
		ctx.streamReferences = stream.References
		ctx.nextHandle = len(stream.References)
		// Don't pre-register stream references as encoded
		// This allows us to match the original payload's reference usage patterns
	}

	return ctx
}

// markAllHandlesEncoded marks every known handle as already emitted.
func (ctx *EncodeContext) markAllHandlesEncoded() {
	if ctx == nil || ctx.encodedOnceHandle == nil {
		return
	}
	for handle := range ctx.encodedOnceHandle {
		ctx.encodedOnceHandle[handle] = true
	}
}

// registerElement registers an element with the encode context
// assigning a handle that matches the original reference index when possible
func (ctx *EncodeContext) registerElement(element Element) {
	if ctx == nil || !ShouldBeReferenced(element) {
		return
	}

	if ctx.encodedElements == nil {
		ctx.encodedElements = make(map[Element]int)
	}
	if ctx.encodedOnceHandle == nil {
		ctx.encodedOnceHandle = make(map[int]bool)
	}

	if handle, exists := ctx.encodedElements[element]; exists {
		// Mark as encoded multiple times - now we can use reference
		ctx.encodedOnceHandle[handle] = true
		return
	}

	if ctx.streamReferences != nil {
		// Check if this element was originally in the stream references
		// If so, use its original handle to maintain compatibility
		for i, ref := range ctx.streamReferences {
			if ref == element {
				// Found exact match, use original handle
				ctx.encodedElements[element] = i
				ctx.encodedOnceHandle[i] = false
				return
			}
		}

		// For strings, also check content-based matching
		if utf, ok := element.(*Utf); ok {
			for i, ref := range ctx.streamReferences {
				if refUtf, ok := ref.(*Utf); ok && refUtf.Contents == utf.Contents {
					// Found content match, use original handle
					ctx.encodedElements[element] = i
					ctx.encodedOnceHandle[i] = false
					return
				}
			}
		}
	}

	handle := ctx.nextHandle
	ctx.encodedElements[element] = handle
	// New elements start as not encoded (need second encounter to use reference)
	ctx.encodedOnceHandle[handle] = false
	ctx.nextHandle++
}

// EncodeElementWithContext encodes an element, checking if it has been encoded in this encoding session
// We don't use stream references directly to avoid introducing references that weren't in the original payload
func EncodeElementWithContext(element Element, ctx *EncodeContext) ([]byte, error) {
	if element == nil {
		return nil, &EncodeError{Message: "element is nil"}
	}

	if ctx != nil {
		if handle, exists := ctx.encodedElements[element]; exists {
			// Use reference only if this element has been encoded multiple times in this session
			// We need to rebuild reference decisions from scratch for compatibility
			if ctx.encodedOnceHandle[handle] {
				handleValue := uint32(handle) + constants.BASE_WIRE_HANDLE
				refElem := NewReference(nil, handleValue)
				return EncodeElement(refElem)
			}
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
	case *ProxyClassDesc:
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
