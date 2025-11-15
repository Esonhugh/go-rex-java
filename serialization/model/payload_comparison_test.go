package model

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"testing"
)

// TestPayloadEncodingComparison compares original payload with re-encoded payload
func TestPayloadEncodingComparison(t *testing.T) {
	// Read ysoserial payloads
	file, err := os.Open("../../ysoserial_payloads.json")
	if err != nil {
		t.Skipf("Skipping test: cannot open ysoserial_payloads.json: %v", err)
		return
	}
	defer file.Close()

	var payloads struct {
		None map[string]struct {
			Status string `json:"status"`
			Bytes  string `json:"bytes"`
		} `json:"none"`
	}

	if err := json.NewDecoder(file).Decode(&payloads); err != nil {
		t.Fatalf("Failed to parse JSON: %v", err)
	}

	// Test CommonsCollections5 (known to match perfectly)
	testPayloads := []string{"CommonsCollections5", "Hibernate1", "JBossInterceptors1", "JSON1", "MozillaRhino1", "MozillaRhino2"}

	for _, payloadName := range testPayloads {
		payload, exists := payloads.None[payloadName]
		if !exists {
			t.Logf("Payload %s not found, skipping", payloadName)
			continue
		}

		t.Run(payloadName, func(t *testing.T) {
			// Decode original payload
			originalBytes, err := base64.StdEncoding.DecodeString(payload.Bytes)
			if err != nil {
				t.Fatalf("Failed to decode payload: %v", err)
			}

			// Parse
			reader := bytes.NewReader(originalBytes)
			stream := NewStream()
			if err := stream.Decode(reader); err != nil {
				t.Fatalf("Failed to decode: %v", err)
			}

			// Encode
			encodedBytes, err := stream.Encode()
			if err != nil {
				t.Fatalf("Failed to encode: %v", err)
			}

			// Compare
			if !bytes.Equal(originalBytes, encodedBytes) {
				t.Logf("Payload %s: original %d bytes, encoded %d bytes", payloadName, len(originalBytes), len(encodedBytes))

				// Find first difference
				minLen := len(originalBytes)
				if len(encodedBytes) < minLen {
					minLen = len(encodedBytes)
				}

				firstDiff := -1
				for i := 0; i < minLen; i++ {
					if originalBytes[i] != encodedBytes[i] {
						firstDiff = i
						break
					}
				}

				if firstDiff >= 0 {
					t.Logf("First difference at position 0x%x (%d)", firstDiff, firstDiff)
					t.Logf("Original: 0x%02x (%c)", originalBytes[firstDiff], originalBytes[firstDiff])
					t.Logf("Encoded:  0x%02x (%c)", encodedBytes[firstDiff], encodedBytes[firstDiff])

					// Show context
					start := firstDiff - 10
					if start < 0 {
						start = 0
					}
					end := firstDiff + 10
					if end > minLen {
						end = minLen
					}

					t.Logf("Context around difference:")
					for i := start; i < end; i++ {
						marker := ""
						if i == firstDiff {
							marker = " <-- DIFF"
						}
						opcodeName := getOpcodeName(originalBytes[i])
						t.Logf("  0x%04x: orig=0x%02x (%s) enc=0x%02x%s",
							i, originalBytes[i], opcodeName, encodedBytes[i], marker)
					}
				}

				// Analyze reference usage
				analyzeReferenceUsage(t, originalBytes, encodedBytes, firstDiff)
			} else {
				t.Logf("✅ Payload %s: Perfect match!", payloadName)
			}
		})
	}
}

func getOpcodeName(b byte) string {
	switch b {
	case 0x70:
		return "TC_NULL"
	case 0x71:
		return "TC_REFERENCE"
	case 0x72:
		return "TC_CLASSDESC"
	case 0x73:
		return "TC_OBJECT"
	case 0x74:
		return "TC_STRING"
	case 0x75:
		return "TC_ARRAY"
	case 0x76:
		return "TC_CLASS"
	case 0x77:
		return "TC_BLOCKDATA"
	case 0x78:
		return "TC_ENDBLOCKDATA"
	default:
		if b >= 0x20 && b <= 0x7e {
			return string(b)
		}
		return "?"
	}
}

func analyzeReferenceUsage(t *testing.T, original, encoded []byte, diffPos int) {
	// Count references in original
	origRefs := 0
	for i := 0; i < len(original)-5; i++ {
		if original[i] == 0x71 { // TC_REFERENCE
			origRefs++
		}
	}

	// Count references in encoded
	encRefs := 0
	for i := 0; i < len(encoded)-5; i++ {
		if encoded[i] == 0x71 { // TC_REFERENCE
			encRefs++
		}
	}

	t.Logf("Reference usage: original has %d TC_REFERENCE, encoded has %d TC_REFERENCE", origRefs, encRefs)

	// Check if difference is related to reference usage
	if diffPos > 0 && diffPos < len(original) {
		if original[diffPos-1] == 0x71 {
			t.Logf("Difference is after a TC_REFERENCE in original")
		}
		if diffPos < len(encoded) && encoded[diffPos] == 0x74 {
			t.Logf("Difference is at a TC_STRING in encoded (might be using string instead of reference)")
		}
		if diffPos < len(encoded) && encoded[diffPos] == 0x71 {
			t.Logf("Difference is at a TC_REFERENCE in encoded")
		}
	}
}
