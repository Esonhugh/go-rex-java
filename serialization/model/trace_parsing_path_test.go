package model

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"testing"
)

// TraceReader wraps a reader to track all reads
type TraceReader struct {
	reader io.Reader
	offset int64
	trace  []ReadTrace
}

type ReadTrace struct {
	Offset int64
	Data   []byte
	Opcode byte
}

func NewTraceReader(reader io.Reader) *TraceReader {
	return &TraceReader{
		reader: reader,
		offset: 0,
		trace:  make([]ReadTrace, 0),
	}
}

func (tr *TraceReader) Read(p []byte) (n int, err error) {
	n, err = tr.reader.Read(p)
	if n > 0 {
		trace := ReadTrace{
			Offset: tr.offset,
			Data:   make([]byte, n),
		}
		copy(trace.Data, p[:n])
		if len(trace.Data) > 0 {
			trace.Opcode = trace.Data[0]
		}
		tr.trace = append(tr.trace, trace)
		tr.offset += int64(n)
	}
	return n, err
}

// TestTraceParsingPath traces the parsing path during full stream decode
func TestTraceParsingPath(t *testing.T) {
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

	// Create trace reader
	traceReader := NewTraceReader(bytes.NewReader(originalBytes))

	// Enable debug logging
	EnableEncodingDebug = true
	defer func() {
		EnableEncodingDebug = false
	}()

	// Decode stream
	stream := NewStream()
	if err := stream.Decode(traceReader); err != nil {
		t.Fatalf("Failed to decode: %v", err)
	}

	// Analyze traces around position 0x2aa
	t.Logf("\n=== Parsing Trace Analysis ===")
	t.Logf("Total traces: %d", len(traceReader.trace))

	// Find traces around position 0x2aa
	t.Logf("\n=== Traces around position 0x2aa-0x2c0 ===")
	targetStart := int64(0x2aa)
	targetEnd := int64(0x2c0)

	for _, trace := range traceReader.trace {
		if trace.Offset >= targetStart && trace.Offset < targetEnd {
			opcodeName := getOpcodeNameTrace(trace.Opcode)
			t.Logf("  Offset 0x%04x: Read %d bytes, first byte=0x%02x (%s)",
				trace.Offset, len(trace.Data), trace.Opcode, opcodeName)
			if len(trace.Data) <= 16 {
				t.Logf("    Data: %x", trace.Data)
			} else {
				t.Logf("    Data (first 16): %x...", trace.Data[:16])
			}
		}
	}

	// Look for ClassDesc decoding
	t.Logf("\n=== Looking for ClassDesc decoding ===")
	classDescCount := 0
	for i, ref := range stream.References {
		if classDesc, ok := ref.(*NewClassDesc); ok {
			classDescCount++
			// Check if this is the target ClassDesc
			if len(classDesc.ClassName.Contents) == 0 && classDesc.SerialVersion == 0x3f4000000000000c {
				t.Logf("✅ Found target ClassDesc at index %d!", i)
				t.Logf("  OmitFlagsAndFields: %v", classDesc.OmitFlagsAndFields)
				if classDesc.ClassAnnotation != nil {
					t.Logf("  ClassAnnotation has %d elements", len(classDesc.ClassAnnotation.Contents))
				} else {
					t.Logf("  ❌ ClassAnnotation is nil!")
				}
			}
		}
	}
	t.Logf("Total NewClassDesc found: %d", classDescCount)

	// Look for ClassDesc in stream.Contents
	contentClassDescCount := 0
	for i, content := range stream.Contents {
		if classDesc, ok := content.(*NewClassDesc); ok {
			contentClassDescCount++
			if len(classDesc.ClassName.Contents) == 0 && classDesc.SerialVersion == 0x3f4000000000000c {
				t.Logf("✅ Found target ClassDesc in Contents at index %d!", i)
				t.Logf("  OmitFlagsAndFields: %v", classDesc.OmitFlagsAndFields)
			}
		}
	}
	t.Logf("Total NewClassDesc in Contents: %d", contentClassDescCount)

	// Analyze what element contains position 0x2aa
	t.Logf("\n=== Finding which element contains position 0x2aa ===")
	offset := int64(0)
	for _, trace := range traceReader.trace {
		if trace.Offset <= targetStart && trace.Offset+int64(len(trace.Data)) > targetStart {
			t.Logf("  Position 0x%04x is in trace at offset 0x%04x (length %d)",
				targetStart, trace.Offset, len(trace.Data))
			relativePos := targetStart - trace.Offset
			t.Logf("  Relative position in trace: %d (0x%02x)", relativePos, relativePos)
			if relativePos < int64(len(trace.Data)) {
				t.Logf("  Byte at position 0x%04x in trace: 0x%02x",
					targetStart, trace.Data[relativePos])
			}
			opcodeName := getOpcodeNameTrace(trace.Opcode)
			t.Logf("  Trace opcode: 0x%02x (%s)", trace.Opcode, opcodeName)
			break
		}
		offset += int64(len(trace.Data))
	}
}

func getOpcodeNameTrace(opcode byte) string {
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
	if name, ok := opcodeNames[opcode]; ok {
		return name
	}
	if opcode >= 0x20 && opcode < 0x7f {
		return fmt.Sprintf("'%c'", opcode)
	}
	return "UNKNOWN"
}
