package goruby

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/esonhugh/go-rex-java/serialization/model"
)

// TestDebugCommonsCollections3Encoding debugs the encoding differences for CommonsCollections3
func TestDebugCommonsCollections3Encoding(t *testing.T) {
	// Load ysoserial payloads
	data, err := os.ReadFile("../ysoserial_payloads.json")
	if err != nil {
		t.Fatalf("Failed to read ysoserial_payloads.json: %v", err)
	}

	var payloads struct {
		None map[string]struct {
			Status string `json:"status"`
			Bytes  string `json:"bytes"`
		} `json:"none"`
	}

	if err := json.Unmarshal(data, &payloads); err != nil {
		t.Fatalf("Failed to parse JSON: %v", err)
	}

	payloadName := "MozillaRhino1"
	payload, exists := payloads.None[payloadName]
	if !exists {
		t.Fatalf("Payload %s not found", payloadName)
	}

	// Decode base64
	originalBytes, err := base64.StdEncoding.DecodeString(payload.Bytes)
	if err != nil {
		t.Fatalf("Failed to decode base64: %v", err)
	}

	fmt.Printf("=== Debugging %s ===\n", payloadName)
	fmt.Printf("Original size: %d bytes\n", len(originalBytes))

	// Parse with Go
	stream := model.NewStream()
	reader := strings.NewReader(string(originalBytes))

	if err := stream.Decode(reader); err != nil {
		t.Fatalf("Failed to decode: %v", err)
	}

	fmt.Printf("Decoded: %d contents, %d references\n", len(stream.Contents), len(stream.References))

	// Debug contents
	fmt.Println("=== Top-level Contents ===")
	for i, content := range stream.Contents {
		fmt.Printf("Content[%d]: %s\n", i, content.String())
	}

	// Debug references
	fmt.Println("=== References ===")
	for i, ref := range stream.References {
		if utf, ok := ref.(*model.Utf); ok && strings.Contains(utf.Contents, "java/lang/Class") {
			fmt.Printf("Ref[%d]: %s\n", i, utf.Contents)
		}
	}

	// Debug what element we're trying to encode at the difference position
	fmt.Println("=== Analyzing difference position ===")
	// We need to figure out what element in the structure corresponds to position 1412
	// This is tricky, but let's try to walk through the encoding process

	// Encode back
	encodedBytes, err := stream.Encode()
	if err != nil {
		t.Fatalf("Failed to encode: %v", err)
	}

	fmt.Printf("Encoded size: %d bytes\n", len(encodedBytes))

	// Compare
	if bytes.Equal(originalBytes, encodedBytes) {
		fmt.Println("✅ Perfect match!")
		return
	}

	fmt.Printf("❌ Mismatch! Original: %d bytes, Encoded: %d bytes\n", len(originalBytes), len(encodedBytes))

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
		fmt.Printf("First difference at position 0x%x (%d)\n", firstDiff, firstDiff)

		// Show context
		start := firstDiff - 20
		if start < 0 {
			start = 0
		}
		end := firstDiff + 20
		if end > minLen {
			end = minLen
		}

		fmt.Printf("Original context:  %s\n", hex.EncodeToString(originalBytes[start:end]))
		fmt.Printf("Encoded context:   %s\n", hex.EncodeToString(encodedBytes[start:end]))
		fmt.Printf("Difference:        ")
		for i := start; i < end; i++ {
			if i == firstDiff {
				fmt.Printf("^^ ")
			} else {
				fmt.Printf("   ")
			}
		}
		fmt.Printf("\n")

		// Try to identify what type of data this is
		if firstDiff < len(originalBytes) {
			opcode := originalBytes[firstDiff]
			fmt.Printf("Original opcode at diff: 0x%02x", opcode)
			switch opcode {
			case 0x70:
				fmt.Printf(" (TC_NULL)")
			case 0x71:
				fmt.Printf(" (TC_REFERENCE)")
			case 0x72:
				fmt.Printf(" (TC_CLASSDESC)")
			case 0x73:
				fmt.Printf(" (TC_OBJECT)")
			case 0x74:
				fmt.Printf(" (TC_STRING)")
			case 0x75:
				fmt.Printf(" (TC_ARRAY)")
			case 0x76:
				fmt.Printf(" (TC_CLASS)")
			case 0x77:
				fmt.Printf(" (TC_BLOCKDATA)")
			case 0x78:
				fmt.Printf(" (TC_ENDBLOCKDATA)")
			case 0x79:
				fmt.Printf(" (TC_RESET)")
			}
			fmt.Printf("\n")
		}
		if firstDiff < len(encodedBytes) {
			opcode := encodedBytes[firstDiff]
			fmt.Printf("Encoded opcode at diff: 0x%02x", opcode)
			switch opcode {
			case 0x70:
				fmt.Printf(" (TC_NULL)")
			case 0x71:
				fmt.Printf(" (TC_REFERENCE)")
			case 0x72:
				fmt.Printf(" (TC_CLASSDESC)")
			case 0x73:
				fmt.Printf(" (TC_OBJECT)")
			case 0x74:
				fmt.Printf(" (TC_STRING)")
			case 0x75:
				fmt.Printf(" (TC_ARRAY)")
			case 0x76:
				fmt.Printf(" (TC_CLASS)")
			case 0x77:
				fmt.Printf(" (TC_BLOCKDATA)")
			case 0x78:
				fmt.Printf(" (TC_ENDBLOCKDATA)")
			case 0x79:
				fmt.Printf(" (TC_RESET)")
			}
			fmt.Printf("\n")
		}

		// Try to decode what the encoded data contains
		if firstDiff < len(encodedBytes)-10 {
			encodedStr := hex.EncodeToString(encodedBytes[firstDiff : firstDiff+10])
			if strings.Contains(encodedStr, "4c6a617661") {
				fmt.Printf("Encoded data appears to contain: Ljava/lang/...\n")
			}
		}
	}

	// Show size difference
	if len(originalBytes) != len(encodedBytes) {
		fmt.Printf("Size difference: original=%d, encoded=%d (diff=%d)\n",
			len(originalBytes), len(encodedBytes), len(encodedBytes)-len(originalBytes))
	}
}
