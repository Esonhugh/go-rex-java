package model

import (
	"bytes"
	"testing"
)

// TestBlockDataRoundTrip tests that BlockData can be decoded and encoded back to the same bytes
func TestBlockDataRoundTrip(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{"Empty", []byte{}},
		{"Single", []byte{0x12}},
		{"Small", []byte{0x01, 0x02, 0x03, 0x04}},
		{"MaxSize", make([]byte, 255)}, // Max size for BlockData
		{"Random", []byte{0xAC, 0xED, 0x00, 0x05, 0x73, 0x72}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Initialize max size test data
			if tt.name == "MaxSize" {
				for i := range tt.data {
					tt.data[i] = byte(i)
				}
			}

			// Create original BlockData
			stream := NewStream()
			original := NewBlockData(stream)
			original.Data = tt.data

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
			decodedBlockData, ok := decoded.(*BlockData)
			if !ok {
				t.Fatalf("Expected *BlockData, got %T", decoded)
			}

			// Verify data
			if !bytes.Equal(decodedBlockData.Data, tt.data) {
				t.Errorf("Data mismatch: expected %x, got %x", tt.data, decodedBlockData.Data)
			}

			// Re-encode and verify bytes match
			reencoded, err := EncodeElement(decodedBlockData)
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

