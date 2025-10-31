package model

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
)

// DebugPayloadDetailed provides very detailed byte-by-byte analysis
func DebugPayloadDetailed(jsonPath string, payloadName string, stopAtPosition int) error {
	data, err := os.ReadFile(jsonPath)
	if err != nil {
		return fmt.Errorf("failed to read file: %w", err)
	}
	
	var payloads map[string]interface{}
	if err := json.Unmarshal(data, &payloads); err != nil {
		return fmt.Errorf("failed to parse JSON: %w", err)
	}
	
	none, ok := payloads["none"].(map[string]interface{})
	if !ok {
		return fmt.Errorf("cannot find 'none' key")
	}
	
	payload, ok := none[payloadName].(map[string]interface{})
	if !ok {
		return fmt.Errorf("cannot find payload %s", payloadName)
	}
	
	bytesStr, ok := payload["bytes"].(string)
	if !ok {
		return fmt.Errorf("cannot find bytes")
	}
	
	bytesData, err := base64.StdEncoding.DecodeString(bytesStr)
	if err != nil {
		return fmt.Errorf("failed to decode base64: %w", err)
	}
	
	fmt.Printf("=== Detailed Analysis of %s ===\n", payloadName)
	fmt.Printf("Total size: %d bytes\n\n", len(bytesData))
	
	// Focus on the problematic region
	start := max(0, stopAtPosition-50)
	end := min(len(bytesData), stopAtPosition+50)
	
	fmt.Printf("Examining bytes around position %d:\n", stopAtPosition)
	fmt.Printf("Range: %d to %d\n\n", start, end)
	
	fmt.Printf("Hex dump:\n")
	for i := start; i < end; i += 16 {
		fmt.Printf("%04x: ", i)
		for j := 0; j < 16 && (i+j) < end; j++ {
			fmt.Printf("%02x ", bytesData[i+j])
		}
		fmt.Printf(" ")
		for j := 0; j < 16 && (i+j) < end; j++ {
			b := bytesData[i+j]
			if b >= 32 && b < 127 {
				fmt.Printf("%c", b)
			} else {
				fmt.Printf(".")
			}
		}
		fmt.Printf("\n")
	}
	
	fmt.Printf("\n=== Annotation at position 205 ===\n")
	// Try to manually decode the annotation starting from where NewClassDesc should have stopped
	// Position 118 (absolute: 122) started NewClassDesc
	// NewClassDesc claimed to consume 83 bytes
	// So it should have ended at 122 + 83 = 205
	
	if stopAtPosition < len(bytesData) {
		fmt.Printf("Byte at position %d: 0x%02x\n", stopAtPosition, bytesData[stopAtPosition])
		if stopAtPosition+1 < len(bytesData) {
			fmt.Printf("Byte at position %d: 0x%02x\n", stopAtPosition+1, bytesData[stopAtPosition+1])
		}
	}
	
	return nil
}

