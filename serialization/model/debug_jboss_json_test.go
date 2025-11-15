package model

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"testing"
)

// TestJBossInterceptors1Debug tests JBossInterceptors1 encoding with detailed debug output
func TestJBossInterceptors1Debug(t *testing.T) {
	testPayloadDebug(t, "JBossInterceptors1", 0x3e0)
}

// TestJSON1Debug tests JSON1 encoding with detailed debug output
func TestJSON1Debug(t *testing.T) {
	testPayloadDebug(t, "JSON1", 0x2b4)
}

// TestMozillaRhino1Debug tests MozillaRhino1 encoding with detailed debug output
func TestMozillaRhino1Debug(t *testing.T) {
	testPayloadDebug(t, "MozillaRhino1", 0x72f)
}

// TestMozillaRhino2Debug tests MozillaRhino2 encoding with detailed debug output
func TestMozillaRhino2Debug(t *testing.T) {
	testPayloadDebug(t, "MozillaRhino2", 0x34a)
}

func testPayloadDebug(t *testing.T, payloadName string, diffPos int) {
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

	// Analyze difference at specific position
	if diffPos < len(originalBytes) && diffPos < len(encodedBytes) {
		t.Logf("\n=== Analysis at position 0x%x ===", diffPos)
		t.Logf("Original byte: 0x%02x", originalBytes[diffPos])
		t.Logf("Encoded byte:  0x%02x", encodedBytes[diffPos])

		// Show more context
		start := diffPos - 20
		if start < 0 {
			start = 0
		}
		end := diffPos + 20
		if end > len(originalBytes) {
			end = len(originalBytes)
		}
		if end > len(encodedBytes) {
			end = len(encodedBytes)
		}

		t.Logf("\nContext around difference:")
		for i := start; i < end; i++ {
			marker := " "
			if i == diffPos {
				marker = "<-- DIFF"
			}
			if i < len(originalBytes) && i < len(encodedBytes) {
				t.Logf("  0x%04x: orig=0x%02x enc=0x%02x %s", i, originalBytes[i], encodedBytes[i], marker)
			}
		}

		// Analyze opcodes
		origOpcode := originalBytes[diffPos]
		encOpcode := encodedBytes[diffPos]

		opcodeNames := map[byte]string{
			0x70: "TC_NULL",
			0x71: "TC_REFERENCE",
			0x72: "TC_CLASSDESC",
			0x73: "TC_OBJECT",
			0x74: "TC_STRING",
			0x75: "TC_ARRAY",
			0x76: "TC_CLASS",
			0x77: "TC_BLOCKDATA",
			0x78: "TC_ENDBLOCKDATA",
			0x7b: "TC_EXCEPTION",
			0x7c: "TC_LONGSTRING",
			0x7d: "TC_PROXYCLASSDESC",
			0x7e: "TC_ENUM",
		}

		origName := opcodeNames[origOpcode]
		if origName == "" {
			origName = fmt.Sprintf("0x%02x", origOpcode)
		}

		encName := opcodeNames[encOpcode]
		if encName == "" {
			encName = fmt.Sprintf("0x%02x", encOpcode)
		}

		t.Logf("\nOpcode analysis:")
		t.Logf("Original: %s (0x%02x)", origName, origOpcode)
		t.Logf("Encoded:  %s (0x%02x)", encName, encOpcode)

		// Check if it's a reference issue
		if origOpcode == 0x72 && encOpcode == 0x73 {
			t.Logf("⚠️  Issue: TC_CLASSDESC expected, but TC_OBJECT found")
			t.Logf("This might indicate a reference was used instead of a full class description")
		} else if origOpcode == 0x77 && encOpcode == 0x01 {
			t.Logf("⚠️  Issue: TC_BLOCKDATA expected, but 0x01 found")
			t.Logf("This might indicate a TC_BLOCKDATA encoding issue")
		}
	}

	// Compare reference usage
	originalRefs := countTCReferences(originalBytes)
	encodedRefs := countTCReferences(encodedBytes)
	t.Logf("\n=== Reference Usage ===")
	t.Logf("Original: %d TC_REFERENCE", originalRefs)
	t.Logf("Encoded:  %d TC_REFERENCE", encodedRefs)
	t.Logf("Difference: %d", encodedRefs-originalRefs)
}
