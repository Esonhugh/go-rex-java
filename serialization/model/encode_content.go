package model

import (
	"github.com/esonhugh/go-rex-java/constants"
)

// encodeContentWithContext encodes a content element with context support
// This handles top-level contents and delegates to element-specific encoding
func encodeContentWithContext(element Element, ctx *EncodeContext) ([]byte, error) {
	if element == nil {
		return nil, &EncodeError{Message: "element is nil"}
	}

	// Check if element should use TC_REFERENCE
	if ctx != nil {
		// First check stream references using content-based matching
		refIndex := findReferenceIndexByContent(element, ctx.streamReferences)
		if refIndex >= 0 {
			handle := uint32(refIndex) + constants.BASE_WIRE_HANDLE
			refElem := NewReference(nil, handle)
			return EncodeElement(refElem)
		}

		// Check if already encoded in this session
		if handle, exists := ctx.encodedElements[element]; exists {
			// Try to find in stream references first
			refIndex := findReferenceIndexByContent(element, ctx.streamReferences)
			if refIndex >= 0 {
				handle = refIndex
			}
			handleValue := uint32(handle) + constants.BASE_WIRE_HANDLE
			refElem := NewReference(nil, handleValue)
			return EncodeElement(refElem)
		}
	}

	// Use EncodeElementWithContext which handles all element types
	return EncodeElementWithContext(element, ctx)
}

