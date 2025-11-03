package model

import (
	"bytes"
	"testing"
)

// TestAnnotationRoundTrip tests that Annotation can be decoded and encoded back to the same bytes
func TestAnnotationRoundTrip(t *testing.T) {
	tests := []struct {
		name     string
		contents []Element
	}{
		{"Empty", []Element{NewEndBlockData(nil)}},
		{"WithUtf", []Element{
			NewUtf(nil, "annotation"),
			NewEndBlockData(nil),
		}},
		{"WithMultiple", []Element{
			NewUtf(nil, "key1"),
			NewUtf(nil, "value1"),
			NewBlockData(nil),
			NewEndBlockData(nil),
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stream := NewStream()

			// Create original Annotation
			original := NewAnnotation(stream)
			original.Contents = tt.contents

			// Encode it
			encoded, err := original.Encode()
			if err != nil {
				t.Fatalf("Failed to encode: %v", err)
			}

			// Decode it back (Annotation is decoded as part of NewClassDesc, but we can test directly)
			// However, Annotation.Decode() expects to read from stream until EndBlockData
			// So we need to encode with EndBlockData at the end
			reader := bytes.NewReader(encoded)
			decoded := NewAnnotation(stream)
			err = decoded.Decode(reader, stream)
			if err != nil {
				t.Fatalf("Failed to decode: %v", err)
			}

			// Verify contents count (should match, excluding EndBlockData which is consumed)
			expectedCount := len(tt.contents)
			if len(decoded.Contents) != expectedCount {
				t.Errorf("Contents count mismatch: expected %d, got %d", expectedCount, len(decoded.Contents))
			}

			// Re-encode and verify bytes match
			reencoded, err := decoded.Encode()
			if err != nil {
				t.Fatalf("Failed to re-encode: %v", err)
			}

			if !bytes.Equal(encoded, reencoded) {
				t.Errorf("Re-encoded data doesn't match original")
				t.Errorf("Original length: %d, Re-encoded length: %d", len(encoded), len(reencoded))
			}
		})
	}
}

