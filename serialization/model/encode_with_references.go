package model

import "github.com/esonhugh/go-rex-java/constants"

// EncodeElementWithReferences encodes an element, checking if it should use TC_REFERENCE
// This is a convenience function that creates a context from stream
// For better control, use EncodeElementWithContext with a shared context
func EncodeElementWithReferences(element Element, stream *Stream) ([]byte, error) {
	if stream == nil {
		// No stream context, encode normally
		return EncodeElement(element)
	}

	if idx := findReferenceIndexByContent(element, stream.References); idx >= 0 {
		handle := uint32(idx) + constants.BASE_WIRE_HANDLE
		refElem := NewReference(nil, handle)
		return EncodeElement(refElem)
	}

	ctx := NewEncodeContext(stream)
	ctx.markAllHandlesEncoded()
	return EncodeElementWithContext(element, ctx)
}

// ShouldBeReferenced checks if an element type should be added to references when decoded
func ShouldBeReferenced(element Element) bool {
	switch element.(type) {
	case *Utf, *LongUtf, *NewObject, *NewArray, *NewClass, *NewClassDesc, *ProxyClassDesc, *NewEnum:
		return true
	default:
		return false
	}
}
