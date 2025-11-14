package model

// EncodeElementWithReferences encodes an element, checking if it should use TC_REFERENCE
// This is a convenience function that creates a context from stream
// For better control, use EncodeElementWithContext with a shared context
func EncodeElementWithReferences(element Element, stream *Stream) ([]byte, error) {
	if stream == nil {
		// No stream context, encode normally
		return EncodeElement(element)
	}

	// Create context and use EncodeElementWithContext which properly checks referencedIndices
	// Don't use findReferenceIndexByContent directly here, as it doesn't check if the element
	// was actually referenced in the original stream
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
