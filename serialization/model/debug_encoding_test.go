package model

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"testing"
)

// TestHibernate1EncodingDebug tests Hibernate1 encoding with detailed debug output
func TestHibernate1EncodingDebug(t *testing.T) {
	testPayloadEncodingDebug(t, "Hibernate1", "[[B")
}

// TestMozillaRhino2EncodingDebug tests MozillaRhino2 encoding with detailed debug output
func TestMozillaRhino2EncodingDebug(t *testing.T) {
	testPayloadEncodingDebug(t, "MozillaRhino2", "")
}

func testPayloadEncodingDebug(t *testing.T, payloadName string, targetString string) {
	// Read payload
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

	payload, exists := payloads.None[payloadName]
	if !exists {
		t.Skipf("%s payload not found", payloadName)
		return
	}

	// Decode
	originalBytes, err := base64.StdEncoding.DecodeString(payload.Bytes)
	if err != nil {
		t.Fatalf("Failed to decode payload: %v", err)
	}

	reader := bytes.NewReader(originalBytes)
	stream := NewStream()
	if err := stream.Decode(reader); err != nil {
		t.Fatalf("Failed to decode: %v", err)
	}

	t.Logf("=== Decoded %s ===", payloadName)
	t.Logf("Contents: %d", len(stream.Contents))
	t.Logf("References: %d", len(stream.References))

	// Count referenced indices
	referencedCount := 0
	for _, referenced := range stream.ReferencedIndices {
		if referenced {
			referencedCount++
		}
	}
	t.Logf("Referenced indices: %d out of %d", referencedCount, len(stream.References))

	// Find target string if specified
	if targetString != "" {
		targetIndex := -1
		for i, ref := range stream.References {
			if utf, ok := ref.(*Utf); ok && utf.Contents == targetString {
				targetIndex = i
				t.Logf("Found target string \"%s\" at reference index %d", targetString, i)
				t.Logf("Was referenced in original: %v", stream.ReferencedIndices != nil && stream.ReferencedIndices[i])
				break
			}
		}
		if targetIndex < 0 {
			t.Logf("⚠️  Target string \"%s\" not found in references", targetString)
		}
	}

	// Enable debug output
	EnableEncodingDebug = true
	defer func() {
		EnableEncodingDebug = false
	}()

	// Encode
	t.Logf("\n=== Encoding %s ===", payloadName)
	encodedBytes, err := stream.Encode()
	if err != nil {
		t.Fatalf("Failed to encode: %v", err)
	}

	t.Logf("Original size: %d bytes", len(originalBytes))
	t.Logf("Encoded size: %d bytes", len(encodedBytes))
	t.Logf("Size difference: %d bytes", len(encodedBytes)-len(originalBytes))

	// Find first difference
	firstDiff := -1
	minLen := len(originalBytes)
	if len(encodedBytes) < minLen {
		minLen = len(encodedBytes)
	}

	for i := 0; i < minLen; i++ {
		if originalBytes[i] != encodedBytes[i] {
			firstDiff = i
			break
		}
	}

	if firstDiff >= 0 {
		t.Logf("\n=== First Difference ===")
		t.Logf("Position: 0x%x (%d)", firstDiff, firstDiff)
		t.Logf("Original: 0x%02x", originalBytes[firstDiff])
		t.Logf("Encoded:  0x%02x", encodedBytes[firstDiff])

		// Show context
		start := firstDiff - 10
		if start < 0 {
			start = 0
		}
		end := firstDiff + 10
		if end > minLen {
			end = minLen
		}

		t.Logf("\nContext around difference:")
		for i := start; i < end; i++ {
			marker := " "
			if i == firstDiff {
				marker = "<-- DIFF"
			}
			if i < len(originalBytes) && i < len(encodedBytes) {
				t.Logf("  0x%04x: orig=0x%02x enc=0x%02x %s", i, originalBytes[i], encodedBytes[i], marker)
			}
		}
	} else {
		t.Logf("\n✅ No differences found in first %d bytes", minLen)
	}

	// Compare reference usage
	originalRefs := countTCReferences(originalBytes)
	encodedRefs := countTCReferences(encodedBytes)
	t.Logf("\n=== Reference Usage ===")
	t.Logf("Original: %d TC_REFERENCE", originalRefs)
	t.Logf("Encoded:  %d TC_REFERENCE", encodedRefs)
	t.Logf("Difference: %d", encodedRefs-originalRefs)
}

func countTCReferences(data []byte) int {
	count := 0
	for i := 0; i < len(data); i++ {
		if data[i] == 0x71 { // TC_REFERENCE
			count++
		}
	}
	return count
}
