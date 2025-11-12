package model

// findReferenceIndexByContent finds the index of an element in stream references
// by pointer identity first, then by content for certain element types.
// Java serialization assigns references based on object identity, but for content-equivalent
// objects (especially strings), we can reuse references for better compatibility.
func findReferenceIndexByContent(element Element, streamReferences []Element) int {
	if element == nil || streamReferences == nil {
		return -1
	}

	// First try pointer comparison for exact match
	for i, ref := range streamReferences {
		if ref == element {
			return i
		}
	}

	// For Utf strings, also try content-based matching
	// This helps with compatibility when the same string content appears multiple times
	if utf, ok := element.(*Utf); ok {
		for i, ref := range streamReferences {
			if refUtf, ok := ref.(*Utf); ok {
				if utf.Contents == refUtf.Contents {
					return i
				}
			}
		}
	}

	return -1
}
