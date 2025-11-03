package model

import (
	"bytes"
	"strings"
	"testing"
)

// TestLongUtfRoundTrip tests that LongUtf can be decoded and encoded back to the same bytes
func TestLongUtfRoundTrip(t *testing.T) {
	tests := []struct {
		name    string
		content string
	}{
		{"Empty", ""},
		{"Short", "test"},
		{"Medium", "This is a test string"},
		{"Long", strings.Repeat("A", 1000)},
		{"VeryLong", strings.Repeat("B", 100000)},
		{"Unicode", strings.Repeat("你好", 1000)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create original LongUtf
			stream := NewStream()
			original := NewLongUtf(stream)
			original.Contents = tt.content
			original.Length = uint64(len(tt.content))

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
			decodedLongUtf, ok := decoded.(*LongUtf)
			if !ok {
				t.Fatalf("Expected *LongUtf, got %T", decoded)
			}

			// Verify content
			if decodedLongUtf.Contents != tt.content {
				t.Errorf("Content mismatch: expected %q, got %q", tt.content, decodedLongUtf.Contents)
			}

			// Re-encode and verify bytes match
			reencoded, err := EncodeElement(decodedLongUtf)
			if err != nil {
				t.Fatalf("Failed to re-encode: %v", err)
			}

			if !bytes.Equal(encoded, reencoded) {
				t.Errorf("Re-encoded data doesn't match original")
			}
		})
	}
}

