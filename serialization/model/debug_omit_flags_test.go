package model

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"testing"
)

// TestDebugOmitFlags tests if OmitFlagsAndFields is correctly set
func TestDebugOmitFlags(t *testing.T) {
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

	payload, exists := payloads.None["JSON1"]
	if !exists {
		t.Skipf("JSON1 payload not found")
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

	// Find ClassDesc with OmitFlagsAndFields=true
	for i, content := range stream.Contents {
		if newEnum, ok := content.(*NewEnum); ok {
			if newEnum.EnumClassDesc != nil && newEnum.EnumClassDesc.Description != nil {
				if classDesc, ok := newEnum.EnumClassDesc.Description.(*NewClassDesc); ok {
					if classDesc.OmitFlagsAndFields {
						t.Logf("Found NewEnum at index %d with ClassDesc that has OmitFlagsAndFields=true", i)
						t.Logf("  ClassAnnotation has %d elements", len(classDesc.ClassAnnotation.Contents))

						// Check Annotation contents
						for j, elem := range classDesc.ClassAnnotation.Contents {
							if bd, ok := elem.(*BlockData); ok {
								t.Logf("    Element %d: BlockData, length=%d, data=%x", j, len(bd.Data), bd.Data[:min(len(bd.Data), 8)])
							} else {
								t.Logf("    Element %d: %T", j, elem)
							}
						}
					}
				}
			}
		}
	}
}
