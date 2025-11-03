package model

import (
	"bytes"
	"testing"

	"github.com/esonhugh/go-rex-java/constants"
)

// TestReferenceRoundTrip tests that Reference can be decoded and encoded back to the same bytes
func TestReferenceRoundTrip(t *testing.T) {
	stream := NewStream()

	// Add some elements to create references
	utf1 := NewUtf(stream, "test1")
	utf2 := NewUtf(stream, "test2")
	stream.AddReference(utf1)
	stream.AddReference(utf2)

	tests := []struct {
		name   string
		handle uint32
	}{
		{"FirstReference", constants.BASE_WIRE_HANDLE},
		{"SecondReference", constants.BASE_WIRE_HANDLE + 1},
		{"HighHandle", constants.BASE_WIRE_HANDLE + 100},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create original Reference
			original := NewReference(stream, tt.handle)

			// Encode it
			encoded, err := EncodeElement(original)
			if err != nil {
				t.Fatalf("Failed to encode: %v", err)
			}

			// Decode it back
			reader := bytes.NewReader(encoded)
			decoded, err := DecodeElement(reader, stream)
			if err != nil {
				t.Fatalf("Failed to decode: %v", err)
			}

			// Verify type
			decodedRef, ok := decoded.(*Reference)
			if !ok {
				t.Fatalf("Expected *Reference, got %T", decoded)
			}

			// Verify handle
			if decodedRef.Handle != tt.handle {
				t.Errorf("Handle mismatch: expected 0x%x, got 0x%x", tt.handle, decodedRef.Handle)
			}

			// Re-encode and verify bytes match
			reencoded, err := EncodeElement(decodedRef)
			if err != nil {
				t.Fatalf("Failed to re-encode: %v", err)
			}

			if !bytes.Equal(encoded, reencoded) {
				t.Errorf("Re-encoded data doesn't match original")
			}
		})
	}
}

