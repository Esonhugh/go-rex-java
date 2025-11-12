package model

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"testing"

	"github.com/esonhugh/go-rex-java/constants"
)

// TestReferenceOrderAnalysis analyzes reference order in CommonsBeanutils1
func TestReferenceOrderAnalysis(t *testing.T) {
	// Read CommonsBeanutils1 payload from ysoserial_payloads.json
	payloadBytes, err := readCommonsBeanutils1Payload()
	if err != nil {
		t.Fatalf("Failed to read payload: %v", err)
	}

	// Decode
	reader := bytes.NewReader(payloadBytes)
	stream := NewStream()
	if err := stream.Decode(reader); err != nil {
		t.Fatalf("Failed to decode: %v", err)
	}

	fmt.Printf("Total references: %d\n", len(stream.References))
	fmt.Printf("\nReference order analysis:\n")
	for i, ref := range stream.References {
		handle := uint32(i) + constants.BASE_WIRE_HANDLE
		refType := fmt.Sprintf("%T", ref)
		var content string
		switch r := ref.(type) {
		case *Utf:
			content = r.Contents
			if len(content) > 40 {
				content = content[:40] + "..."
			}
		case *NewObject:
			content = "NewObject"
		case *NewClassDesc:
			if r.ClassName != nil {
				content = r.ClassName.Contents
			} else {
				content = "NewClassDesc(nil)"
			}
		default:
			content = refType
		}
		fmt.Printf("  [%d] handle=0x%x, type=%s, content=%q\n", i, handle, refType, content)
	}

	// Analyze positions 168 and 475 in original payload
	fmt.Printf("\nAnalyzing problematic positions in original payload:\n")
	
	// Position 168: context shows "617261746f7271007e00014c000870726f706572"
	// This is: "arator" + TC_REFERENCE(0x71) + handle(0x007e0001) + "L" + "proper"
	// So it should reference index 1
	if len(stream.References) > 1 {
		fmt.Printf("Position 168: should reference index 1\n")
		fmt.Printf("  Reference[1]: %T, %s\n", stream.References[1], stream.References[1].String())
		if len(stream.References) > 0 {
			fmt.Printf("  Reference[0]: %T, %s\n", stream.References[0], stream.References[0].String())
		}
	}

	// Position 475: context shows "055f6e616d6571007e00044c00115f6f75747075"
	// This is: ... + TC_REFERENCE(0x71) + handle(0x007e0004) + "L" + "_output"
	// So it should reference index 4
	if len(stream.References) > 4 {
		fmt.Printf("Position 475: should reference index 4\n")
		fmt.Printf("  Reference[4]: %T, %s\n", stream.References[4], stream.References[4].String())
		if len(stream.References) > 2 {
			fmt.Printf("  Reference[2]: %T, %s\n", stream.References[2], stream.References[2].String())
		}
	}

	// Now encode and check what references are used
	encoded, err := stream.Encode()
	if err != nil {
		t.Fatalf("Failed to encode: %v", err)
	}

	// Check position 168 in encoded data
	if len(encoded) > 168 {
		ctxStart := max(0, 168-10)
		ctxEnd := min(len(encoded), 168+10)
		ctx := encoded[ctxStart:ctxEnd]
		fmt.Printf("\nEncoded position 168 context: %s\n", hex.EncodeToString(ctx))
		
		// Parse TC_REFERENCE at position 168
		if encoded[168] == constants.TC_REFERENCE && len(encoded) >= 168+5 {
			handleBytes := encoded[169:173]
			handle := uint32(handleBytes[0])<<24 | uint32(handleBytes[1])<<16 | uint32(handleBytes[2])<<8 | uint32(handleBytes[3])
			index := int(handle - constants.BASE_WIRE_HANDLE)
			fmt.Printf("  Encoded handle: 0x%x (index %d)\n", handle, index)
			fmt.Printf("  Expected handle: 0x%x (index 1)\n", uint32(1)+constants.BASE_WIRE_HANDLE)
		}
	}

	// Check position 475 in encoded data
	if len(encoded) > 475 {
		ctxStart := max(0, 475-10)
		ctxEnd := min(len(encoded), 475+10)
		ctx := encoded[ctxStart:ctxEnd]
		fmt.Printf("\nEncoded position 475 context: %s\n", hex.EncodeToString(ctx))
		
		// Parse TC_REFERENCE at position 475
		if encoded[475] == constants.TC_REFERENCE && len(encoded) >= 475+5 {
			handleBytes := encoded[476:480]
			handle := uint32(handleBytes[0])<<24 | uint32(handleBytes[1])<<16 | uint32(handleBytes[2])<<8 | uint32(handleBytes[3])
			index := int(handle - constants.BASE_WIRE_HANDLE)
			fmt.Printf("  Encoded handle: 0x%x (index %d)\n", handle, index)
			fmt.Printf("  Expected handle: 0x%x (index 4)\n", uint32(4)+constants.BASE_WIRE_HANDLE)
		}
	}
}

// TestEncodeDecodeReversibility tests that encode-decode is reversible
func TestEncodeDecodeReversibility(t *testing.T) {
	// Read CommonsBeanutils1 payload
	payloadBytes, err := readCommonsBeanutils1Payload()
	if err != nil {
		t.Fatalf("Failed to read payload: %v", err)
	}

	// First decode
	reader1 := bytes.NewReader(payloadBytes)
	stream1 := NewStream()
	if err := stream1.Decode(reader1); err != nil {
		t.Fatalf("Failed to decode: %v", err)
	}

	// First encode
	encoded1, err := stream1.Encode()
	if err != nil {
		t.Fatalf("Failed to encode: %v", err)
	}

	// Second decode
	reader2 := bytes.NewReader(encoded1)
	stream2 := NewStream()
	if err := stream2.Decode(reader2); err != nil {
		t.Fatalf("Failed to decode re-encoded: %v", err)
	}

	// Second encode
	encoded2, err := stream2.Encode()
	if err != nil {
		t.Fatalf("Failed to re-encode: %v", err)
	}

	// Compare - this should match for reversibility
	if !bytes.Equal(encoded1, encoded2) {
		t.Errorf("Encode-decode is not reversible!")
		t.Errorf("First encode length: %d", len(encoded1))
		t.Errorf("Second encode length: %d", len(encoded2))
		
		// Find differences
		minLen := len(encoded1)
		if len(encoded2) < minLen {
			minLen = len(encoded2)
		}
		diffs := 0
		for i := 0; i < minLen && diffs < 10; i++ {
			if encoded1[i] != encoded2[i] {
				t.Errorf("Difference at position %d: 0x%02x vs 0x%02x", i, encoded1[i], encoded2[i])
				diffs++
			}
		}
	} else {
		t.Logf("✅ Encode-decode is reversible! Length: %d bytes", len(encoded1))
	}

	// Verify references are the same
	if len(stream1.References) != len(stream2.References) {
		t.Errorf("Reference count mismatch: %d vs %d", len(stream1.References), len(stream2.References))
	} else {
		t.Logf("✅ Reference count matches: %d", len(stream1.References))
	}
}

// Helper functions
func readCommonsBeanutils1Payload() ([]byte, error) {
	// Read from ysoserial_payloads.json
	file, err := os.Open("../../ysoserial_payloads.json")
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var data map[string]interface{}
	decoder := json.NewDecoder(file)
	if err := decoder.Decode(&data); err != nil {
		return nil, err
	}

	if bash, ok := data["bash"].(map[string]interface{}); ok {
		if cb1, ok := bash["CommonsBeanutils1"].(map[string]interface{}); ok {
			if bytesStr, ok := cb1["bytes"].(string); ok {
				payloadBytes, err := base64.StdEncoding.DecodeString(bytesStr)
				if err != nil {
					return nil, err
				}
				return payloadBytes, nil
			}
		}
	}

	return nil, fmt.Errorf("CommonsBeanutils1 payload not found")
}

// min and max are already defined in payload_debug.go

