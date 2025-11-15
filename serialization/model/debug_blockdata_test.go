package model

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"testing"
)

// TestDebugBlockDataAtPosition tests BlockData at specific position
func TestDebugBlockDataAtPosition(t *testing.T) {
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

	// Find the ClassDesc that contains the BlockData at position 0x2b4
	// Position 0x2b4 should be in a ClassAnnotation
	t.Logf("Total contents: %d", len(stream.Contents))
	t.Logf("Total references: %d", len(stream.References))

	// Target BlockData data: 0000001000000001 (8 bytes)
	targetData := []byte{0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x01}
	t.Logf("Looking for BlockData with data: %x", targetData)

	// Search for ClassDesc with BlockData in ClassAnnotation
	for i, content := range stream.Contents {
		if classDesc, ok := content.(*NewClassDesc); ok {
			if classDesc.ClassAnnotation != nil {
				annotation := classDesc.ClassAnnotation
				t.Logf("Found ClassDesc at index %d with ClassAnnotation (%d elements)", i, len(annotation.Contents))

				// Check if Annotation contains BlockData with specific data
				for j, elem := range annotation.Contents {
					if bd, ok := elem.(*BlockData); ok {
						showLen := len(bd.Data)
						if showLen > 8 {
							showLen = 8
						}
						dataPrefix := bd.Data
						if len(bd.Data) > 8 {
							dataPrefix = bd.Data[:8]
						}
						if len(bd.Data) == 8 && bytes.Equal(bd.Data, targetData) {
							t.Logf("  ✅ Found target BlockData at Annotation index %d with data: %x", j, bd.Data)
							t.Logf("    This matches the BlockData at position 0x2b4!")
						} else {
							t.Logf("  BlockData at Annotation index %d: length=%d, data=%x", j, len(bd.Data), dataPrefix)
						}
					} else {
						t.Logf("  Element at Annotation index %d: type=%T", j, elem)
					}
				}
			}
		} else if newEnum, ok := content.(*NewEnum); ok {
			// Check NewEnum's ClassDesc
			if newEnum.EnumClassDesc != nil && newEnum.EnumClassDesc.Description != nil {
				if classDesc, ok := newEnum.EnumClassDesc.Description.(*NewClassDesc); ok {
					if classDesc.ClassAnnotation != nil {
						annotation := classDesc.ClassAnnotation
						t.Logf("Found NewEnum at index %d with ClassDesc ClassAnnotation (%d elements)", i, len(annotation.Contents))

						// Check if Annotation contains BlockData with specific data
						for j, elem := range annotation.Contents {
							if bd, ok := elem.(*BlockData); ok {
								if len(bd.Data) == 8 && bd.Data[0] == 0x00 && bd.Data[1] == 0x00 && bd.Data[4] == 0x10 {
									t.Logf("  ✅ Found BlockData at Annotation index %d with data: %x", j, bd.Data)
									t.Logf("    This matches the BlockData at position 0x2b4!")
								} else {
									t.Logf("  BlockData at Annotation index %d: length=%d, data=%x", j, len(bd.Data), bd.Data[:min(len(bd.Data), 8)])
								}
							} else {
								t.Logf("  Element at Annotation index %d: type=%T", j, elem)
							}
						}
					}
				}
			}
		}
	}
}
