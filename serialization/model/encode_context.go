package model

import (
	"fmt"
	"log"

	"github.com/esonhugh/go-rex-java/constants"
)

// EnableEncodingDebug enables debug output for encoding process
var EnableEncodingDebug = false

// debugLog logs debug message if EnableEncodingDebug is true
func debugLog(format string, args ...interface{}) {
	if EnableEncodingDebug {
		log.Printf("[ENCODE DEBUG] "+format, args...)
	}
}

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
	// referencedIndices tracks which reference indices were actually referenced in the original stream
	referencedIndices map[int]bool
	// nextHandle tracks the next available handle index for new elements
	nextHandle int
}

// NewEncodeContext creates a new encode context
func NewEncodeContext(stream *Stream) *EncodeContext {
	ctx := &EncodeContext{
		encodedElements:   make(map[Element]int),
		encodedOnceHandle: make(map[int]bool),
		streamReferences:  stream.References,
		referencedIndices: stream.ReferencedIndices,
		nextHandle:        len(stream.References), // Start after existing references
	}

	// Pre-register stream references with their original indices
	// Only pre-register references that were actually referenced in the original stream
	// This ensures elements use their original handles for consistent encoding
	if stream != nil && stream.References != nil {
		for i, ref := range stream.References {
			// Only pre-register if this reference index was actually used in the original stream
			if stream.ReferencedIndices != nil && stream.ReferencedIndices[i] {
				ctx.encodedElements[ref] = i
				ctx.encodedOnceHandle[i] = false // Mark as not yet encoded
			}
		}
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
		// Mark as encoded multiple times - now we can use reference (if it was referenced in original)
		if utf, ok := element.(*Utf); ok {
			debugLog("registerElement: String %q already registered with handle %d - marking as encoded multiple times", utf.Contents, handle)
		}
		ctx.encodedOnceHandle[handle] = true
		return
	}

	// Check if element is in stream references
	// Only use original index if it was actually referenced in the original stream
	if ctx.streamReferences != nil {
		// Try exact pointer matching first
		for i, ref := range ctx.streamReferences {
			if ref == element {
				// Found in stream references - only use original index if it was referenced
				wasReferenced := ctx.referencedIndices != nil && ctx.referencedIndices[i]
				if utf, ok := element.(*Utf); ok {
					debugLog("registerElement: String %q found in stream references at index %d (pointer match), wasReferenced=%v", utf.Contents, i, wasReferenced)
				}
				if ctx.referencedIndices != nil && ctx.referencedIndices[i] {
					ctx.encodedElements[element] = i
					ctx.encodedOnceHandle[i] = false // Mark as not yet encoded
					if utf, ok := element.(*Utf); ok {
						debugLog("registerElement: Registered string %q with handle %d (was referenced)", utf.Contents, i)
					}
					return
				}
				// Element is in stream references but was never referenced
				// Don't register it - it should always use full encoding
				if utf, ok := element.(*Utf); ok {
					debugLog("registerElement: String %q is in stream references but was NEVER referenced - NOT registering", utf.Contents)
				}
				return
			}
		}

		// For strings, also check content-based matching
		if utf, ok := element.(*Utf); ok {
			for i, ref := range ctx.streamReferences {
				if refUtf, ok := ref.(*Utf); ok && refUtf.Contents == utf.Contents {
					// Found content match - only use original index if it was referenced
					wasReferenced := ctx.referencedIndices != nil && ctx.referencedIndices[i]
					debugLog("registerElement: String %q found in stream references at index %d (content match), wasReferenced=%v", utf.Contents, i, wasReferenced)
					if ctx.referencedIndices != nil && ctx.referencedIndices[i] {
						ctx.encodedElements[element] = i
						ctx.encodedOnceHandle[i] = false // Mark as not yet encoded
						debugLog("registerElement: Registered string %q with handle %d (was referenced)", utf.Contents, i)
						return
					}
					// String is in stream references but was never referenced
					// Don't register it - it should always use full encoding
					debugLog("registerElement: String %q is in stream references but was NEVER referenced - NOT registering", utf.Contents)
					return
				}
			}
		}
	}

	// Element is not in stream references - assign new handle
	// Note: New elements won't use references unless they appear multiple times
	handle := ctx.nextHandle
	ctx.encodedElements[element] = handle
	ctx.encodedOnceHandle[handle] = false
	if utf, ok := element.(*Utf); ok {
		debugLog("registerElement: String %q not in stream references - assigned new handle %d", utf.Contents, handle)
	}
	ctx.nextHandle++
}

// EncodeElementWithContext encodes an element, checking if it has been encoded in this encoding session
func EncodeElementWithContext(element Element, ctx *EncodeContext) ([]byte, error) {
	if element == nil {
		return nil, &EncodeError{Message: "element is nil"}
	}

	// Debug: Log element being encoded (always, not just if ShouldBeReferenced)
	if utf, ok := element.(*Utf); ok {
		debugLog("EncodeElementWithContext: Encoding Utf string: %q, ctx=%v, ShouldBeReferenced=%v", utf.Contents, ctx != nil, ShouldBeReferenced(element))
	}

	// Check if this element should be referenced
	if ctx != nil && ShouldBeReferenced(element) {
		// Debug: Log element being encoded
		if utf, ok := element.(*Utf); ok {
			debugLog("Encoding Utf string: %q", utf.Contents)
		}

		// First, check if element is in stream references (using content matching for strings)
		// If it's in stream references but was NOT referenced in the original stream,
		// we should always use full encoding, not reference
		// This check must happen BEFORE checking encodedElements to prevent incorrect registration
		if ctx.streamReferences != nil {
			// For strings, check content matching
			if utf, ok := element.(*Utf); ok {
				for i, ref := range ctx.streamReferences {
					if refUtf, ok := ref.(*Utf); ok && refUtf.Contents == utf.Contents {
						// Found content match in stream references
						wasReferenced := ctx.referencedIndices != nil && ctx.referencedIndices[i]
						debugLog("Found string %q in stream references at index %d, wasReferenced=%v", utf.Contents, i, wasReferenced)
						if ctx.referencedIndices != nil && !ctx.referencedIndices[i] {
							// Element is in stream references but was NEVER referenced in original stream
							// Always use full encoding, never use reference
							// Skip all reference checking and encoding registration
							// Continue to encode it normally without registration
							debugLog("String %q is in stream references but was NEVER referenced - using full encoding", utf.Contents)
							goto encodeNormally
						}
						// Element is in stream references AND was referenced in original stream
						// Continue to check if it's already in encodedElements
						debugLog("String %q is in stream references and was referenced - checking encodedElements", utf.Contents)
					}
				}
			}
		}

		// Check if element is already in encodedElements (using pointer matching)
		if handle, exists := ctx.encodedElements[element]; exists {
			if utf, ok := element.(*Utf); ok {
				debugLog("String %q found in encodedElements with handle %d", utf.Contents, handle)
			}
			// Special check: Top-level content objects should never be referenced
			switch element.(type) {
			case *NewObject, *NewArray, *NewClassDesc:
				// Don't use reference for top-level content objects
				break
			default:
				// Only use reference if:
				// 1. Element has been encoded before in this session
				// 2. AND the reference index was actually used in the original stream
				if ctx.encodedOnceHandle[handle] {
					// Check if this reference index was actually used in the original stream
					if ctx.referencedIndices != nil && ctx.referencedIndices[handle] {
						// Element has been encoded before and was referenced in original stream - use reference
						handleValue := uint32(handle) + constants.BASE_WIRE_HANDLE
						if utf, ok := element.(*Utf); ok {
							debugLog("Using TC_REFERENCE for string %q with handle %d (0x%x)", utf.Contents, handle, handleValue)
						}
						refElem := NewReference(nil, handleValue)
						return EncodeElement(refElem)
					}
					// Element was encoded before but was NOT referenced in original stream
					// Use full encoding to match original payload
					if utf, ok := element.(*Utf); ok {
						debugLog("String %q was encoded before but was NOT referenced in original - using full encoding", utf.Contents)
					}
				} else {
					// Element is registered but not yet encoded - mark as encoded
					// and continue to encode it normally
					ctx.encodedOnceHandle[handle] = true
					if utf, ok := element.(*Utf); ok {
						debugLog("String %q is registered but not yet encoded - marking as encoded", utf.Contents)
					}
				}
			}
		}
	}

encodeNormally:
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
	case *NewEnum:
		encoded, err = e.EncodeWithContext(ctx)
	case *BlockData:
		debugLog("EncodeElementWithContext: Encoding BlockData, length=%d", len(e.Data))
		encoded, err = e.EncodeWithContext(ctx)
		if err == nil {
			debugLog("EncodeElementWithContext: BlockData encoded, opcode will be 0x%02x, body length=%d", opcode, len(encoded))
		}
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
	// But skip registration if element is in stream references but was never referenced
	// This was already checked at the beginning of the function, so we need to track it
	if ctx != nil && ShouldBeReferenced(element) {
		// Check if element is in stream references but was never referenced
		// If so, don't register it - it should always use full encoding
		shouldSkipRegistration := false
		if ctx.streamReferences != nil {
			// For strings, check content matching
			if utf, ok := element.(*Utf); ok {
				for i, ref := range ctx.streamReferences {
					if refUtf, ok := ref.(*Utf); ok && refUtf.Contents == utf.Contents {
						// Found content match in stream references
						if ctx.referencedIndices != nil && !ctx.referencedIndices[i] {
							// Element is in stream references but was NEVER referenced in original stream
							// Don't register it - it should always use full encoding
							shouldSkipRegistration = true
							break
						}
					}
				}
			}
		}
		// Only register if we didn't skip registration
		if !shouldSkipRegistration {
			ctx.registerElement(element)
		}
		// Note: If we skipped registration, the element will never be in encodedElements,
		// so it will always be encoded as a full element, never as a reference
	}

	return result, nil
}
