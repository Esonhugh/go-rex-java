package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/esonhugh/go-rex-java/serialization/model"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Println("Usage: go run analyze_encoding_diff.go <payload_name>")
		os.Exit(1)
	}

	payloadName := os.Args[1]

	data, _ := os.ReadFile("ysoserial_payloads.json")
	var payloads struct {
		None map[string]struct {
			Status string `json:"status"`
			Bytes  string `json:"bytes"`
		} `json:"none"`
	}
	json.Unmarshal(data, &payloads)

	payloadBytes, _ := base64.StdEncoding.DecodeString(payloads.None[payloadName].Bytes)
	stream := model.NewStream()
	reader := strings.NewReader(string(payloadBytes))

	if err := stream.Decode(reader); err != nil {
		fmt.Printf("Failed to decode %s: %v\n", payloadName, err)
		return
	}

	encoded, err := stream.Encode()
	if err != nil {
		fmt.Printf("Failed to encode %s: %v\n", payloadName, err)
		return
	}

	fmt.Printf("%s encoding analysis:\n", payloadName)
	fmt.Printf("Original size: %d bytes\n", len(payloadBytes))
	fmt.Printf("Encoded size: %d bytes\n", len(encoded))
	fmt.Printf("Size difference: %d bytes\n", len(encoded)-len(payloadBytes))

	// Find first difference
	minLen := len(payloadBytes)
	if len(encoded) < minLen {
		minLen = len(encoded)
	}

	firstDiff := -1
	for i := 0; i < minLen; i++ {
		if payloadBytes[i] != encoded[i] {
			firstDiff = i
			break
		}
	}

	if firstDiff >= 0 {
		fmt.Printf("First difference at position 0x%x (%d)\n", firstDiff, firstDiff)
		fmt.Printf("Original byte: 0x%02x\n", payloadBytes[firstDiff])
		fmt.Printf("Encoded byte:  0x%02x\n", encoded[firstDiff])

		// Show context
		start := firstDiff - 8
		if start < 0 {
			start = 0
		}
		end := firstDiff + 8
		if end > minLen {
			end = minLen
		}

		fmt.Println("Context:")
		for i := start; i < end; i++ {
			marker := ""
			if i == firstDiff {
				marker = " <-- DIFFERENCE"
			}
			fmt.Printf("  0x%04x: 0x%02x (orig) 0x%02x (enc)%s\n",
				i, payloadBytes[i], encoded[i], marker)
		}
	} else if len(encoded) != len(payloadBytes) {
		fmt.Printf("Sizes differ but content matches up to %d bytes\n", minLen)
		if len(encoded) > len(payloadBytes) {
			fmt.Printf("Extra bytes in encoded: %x\n", encoded[minLen:minLen+16])
		} else {
			fmt.Printf("Missing bytes in encoded\n")
		}
	} else {
		fmt.Println("Content matches perfectly!")
	}
}
