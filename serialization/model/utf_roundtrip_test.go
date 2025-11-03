package model

import (
	"bytes"
	"strings"
	"testing"
)

// TestUtfRoundTrip tests that Utf can be decoded and encoded back to the same bytes
func TestUtfRoundTrip(t *testing.T) {
	tests := []struct {
		name    string
		content string
	}{
		{"Empty", ""},
		{"Short", "test"},
		{"Medium", "This is a test string"},
		{"WithSpecialChars", "Hello\nWorld\t!"},
		{"Unicode", "你好世界"},
		{"Long", strings.Repeat("A", 100)},
		{"MaxShort", strings.Repeat("B", 65535)}, // Max uint16
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create original Utf
			stream := NewStream()
			original := NewUtf(stream, tt.content)

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
			decodedUtf, ok := decoded.(*Utf)
			if !ok {
				t.Fatalf("Expected *Utf, got %T", decoded)
			}

			// Verify content
			if decodedUtf.Contents != tt.content {
				t.Errorf("Content mismatch: expected %q, got %q", tt.content, decodedUtf.Contents)
			}

			// Re-encode and verify bytes match
			reencoded, err := EncodeElement(decodedUtf)
			if err != nil {
				t.Fatalf("Failed to re-encode: %v", err)
			}

			if !bytes.Equal(encoded, reencoded) {
				t.Errorf("Re-encoded data doesn't match original")
				t.Errorf("Original: %x", encoded)
				t.Errorf("Re-encoded: %x", reencoded)
			}
		})
	}
}

