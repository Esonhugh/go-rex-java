package model

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"testing"
)

// TestDebugClassDescDecode tests ClassDesc decoding with TC_BLOCKDATA at flags position
func TestDebugClassDescDecode(t *testing.T) {
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

	// Parse the stream until we get to position 0x2aa
	reader := bytes.NewReader(originalBytes)
	stream := NewStream()

	// Decode until we reach the ClassDesc at position 0x2aa
	// Position 0x2a9 is TC_ENUM, position 0x2aa is the start of ClassDesc
	pos := 0x2aa

	// Skip to position 0x2aa
	skipBytes := make([]byte, pos)
	if _, err := reader.Read(skipBytes); err != nil {
		t.Fatalf("Failed to skip to position 0x2aa: %v", err)
	}

	t.Logf("Skipped to position 0x%x", pos)

	// Now decode ClassDesc from position 0x2aa
	// Class name length should be 0x00 0x00
	classDesc := NewNewClassDesc(stream)

	// Decode class name
	classDesc.ClassName = NewUtf(stream, "")
	if err := classDesc.ClassName.Decode(reader, stream); err != nil {
		t.Fatalf("Failed to decode class name: %v", err)
	}
	t.Logf("Class name: %q (length: %d)", classDesc.ClassName.Contents, len(classDesc.ClassName.Contents))

	// Decode serial version
	serialBytes := make([]byte, 8)
	if _, err := reader.Read(serialBytes); err != nil {
		t.Fatalf("Failed to read serial version: %v", err)
	}
	classDesc.SerialVersion = uint64(serialBytes[0])<<56 | uint64(serialBytes[1])<<48 | uint64(serialBytes[2])<<40 | uint64(serialBytes[3])<<32 | uint64(serialBytes[4])<<24 | uint64(serialBytes[5])<<16 | uint64(serialBytes[6])<<8 | uint64(serialBytes[7])
	t.Logf("SerialVersionUID: 0x%016x", classDesc.SerialVersion)

	// Now decode flags - this should detect TC_BLOCKDATA
	peekBuf := make([]byte, 1)
	peekPos := pos + 2 + 8 // After class name (2 bytes) and serialVersionUID (8 bytes)
	if _, err := reader.Read(peekBuf); err != nil {
		t.Fatalf("Failed to read flags: %v", err)
	}
	t.Logf("Peeked byte at position 0x%x: 0x%02x", peekPos, peekBuf[0])

	if peekBuf[0] == 0x77 { // TC_BLOCKDATA
		t.Logf("✅ Detected TC_BLOCKDATA at flags position!")
		// Put the byte back and create a new reader from the remaining bytes
		remainingBytes := append(peekBuf, originalBytes[peekPos+1:]...)
		reader = bytes.NewReader(remainingBytes)

		// Decode ClassAnnotation
		classDesc.ClassAnnotation = NewAnnotation(stream)
		if err := classDesc.ClassAnnotation.Decode(reader, stream); err != nil {
			t.Fatalf("Failed to decode ClassAnnotation: %v", err)
		}

		t.Logf("ClassAnnotation has %d elements", len(classDesc.ClassAnnotation.Contents))
		for i, elem := range classDesc.ClassAnnotation.Contents {
			if bd, ok := elem.(*BlockData); ok {
				t.Logf("  Element %d: BlockData, length=%d, data=%x", i, len(bd.Data), bd.Data[:min(len(bd.Data), 8)])
			} else {
				t.Logf("  Element %d: %T", i, elem)
			}
		}
	} else {
		t.Logf("Flags byte: 0x%02x (not TC_BLOCKDATA)", peekBuf[0])
	}
}
