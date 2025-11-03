package model

import (
	"bytes"
	"testing"
)

// TestBlockDataLongRoundTrip tests that BlockDataLong can be decoded and encoded back to the same bytes
func TestBlockDataLongRoundTrip(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{"Empty", []byte{}},
		{"Small", []byte{0x01, 0x02, 0x03}},
		{"Medium", make([]byte, 1000)},
		{"Large", make([]byte, 65536)},
		{"SmallRandom", []byte{0x01, 0x02, 0x03, 0x04, 0x05}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Initialize test data with patterns
			if tt.name == "Medium" || tt.name == "Large" {
				for i := range tt.data {
					tt.data[i] = byte(i % 256)
				}
			}

			// Create original BlockDataLong
			stream := NewStream()
			original := NewBlockDataLong(stream)
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
			decodedBlockDataLong, ok := decoded.(*BlockDataLong)
			if !ok {
				t.Fatalf("Expected *BlockDataLong, got %T", decoded)
			}

			// Verify data
			if !bytes.Equal(decodedBlockDataLong.Data, tt.data) {
				t.Errorf("Data mismatch: expected length %d, got %d", len(tt.data), len(decodedBlockDataLong.Data))
				if len(decodedBlockDataLong.Data) > 0 && len(tt.data) > 0 {
					t.Errorf("First few bytes - expected: %x, got: %x", tt.data[:min(10, len(tt.data))], decodedBlockDataLong.Data[:min(10, len(decodedBlockDataLong.Data))])
				}
			}

			// Re-encode and verify bytes match
			reencoded, err := EncodeElement(decodedBlockDataLong)
			if err != nil {
				t.Fatalf("Failed to re-encode: %v", err)
			}

			if !bytes.Equal(encoded, reencoded) {
				t.Errorf("Re-encoded data doesn't match original")
			}
		})
	}
}

