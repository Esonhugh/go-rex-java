package model

// findReferenceIndexByContent finds the index of an element in stream references
// by comparing content (especially for Utf strings)
// This ensures we find the correct reference even if pointer addresses differ
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

	// For Utf strings, compare by content
	if utf, ok := element.(*Utf); ok {
		for i, ref := range streamReferences {
			if refUtf, ok := ref.(*Utf); ok {
				// Exact content match
				if utf.Contents == refUtf.Contents {
					return i
				}
			}
		}
	}

	// For LongUtf strings, compare by content
	if longUtf, ok := element.(*LongUtf); ok {
		for i, ref := range streamReferences {
			if refLongUtf, ok := ref.(*LongUtf); ok {
				// Exact content match
				if longUtf.Contents == refLongUtf.Contents {
					return i
				}
			}
		}
	}

	return -1
}
