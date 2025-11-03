package model

import (
	"bytes"
	"testing"
)

// TestElementRoundTrip tests round-trip for simple elements
func TestElementRoundTrip(t *testing.T) {
	tests := []struct {
		name    string
		element Element
	}{
		{"NullReference", NewNullReference(nil)},
		{"EndBlockData", NewEndBlockData(nil)},
		{"Reset", NewReset(nil)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stream := NewStream()

			// Encode element
			encoded, err := EncodeElement(tt.element)
			if err != nil {
				t.Fatalf("Failed to encode: %v", err)
			}

			// Decode it back
			reader := bytes.NewReader(encoded)
			decoded, err := DecodeElement(reader, stream)
			if err != nil {
				t.Fatalf("Failed to decode: %v", err)
			}

			// Verify type matches
			originalType := getElementTypeName(tt.element)
			decodedType := getElementTypeName(decoded)
			if originalType != decodedType {
				t.Errorf("Type mismatch: expected %s, got %s", originalType, decodedType)
			}

			// Re-encode and verify bytes match
			reencoded, err := EncodeElement(decoded)
			if err != nil {
				t.Fatalf("Failed to re-encode: %v", err)
			}

			if !bytes.Equal(encoded, reencoded) {
				t.Errorf("Re-encoded data doesn't match original")
			}
		})
	}
}

func getElementTypeName(elem Element) string {
	switch elem.(type) {
	case *NullReference:
		return "NullReference"
	case *EndBlockData:
		return "EndBlockData"
	case *Reset:
		return "Reset"
	default:
		return "Unknown"
	}
}

