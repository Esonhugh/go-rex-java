package model

import (
	"bytes"
	"testing"

	"github.com/esonhugh/go-rex-java/constants"
)

// TestNewClassDescRoundTrip tests that NewClassDesc can be decoded and encoded back to the same bytes
func TestNewClassDescRoundTrip(t *testing.T) {
	stream := NewStream()

	// Create a complete NewClassDesc
	original := NewNewClassDesc(stream)
	original.ClassName = NewUtf(stream, "java.io.File")
	original.SerialVersion = 0x042da4450e0de4ff
	original.Flags = constants.SC_SERIALIZABLE

	// Add a field
	field := NewField(stream)
	field.Type = Object
	field.Name = NewUtf(stream, "path")
	field.FieldType = NewUtf(stream, "Ljava/lang/String;")
	original.Fields = []*Field{field}

	// Add class annotation (empty annotation with EndBlockData)
	original.ClassAnnotation = NewAnnotation(stream)
	original.ClassAnnotation.Contents = []Element{NewEndBlockData(stream)}

	// Add super class (NullReference)
	original.SuperClass = NewClassDescInstance(stream)
	original.SuperClass.Description = NewNullReference(stream)

	// Encode with opcode (via EncodeElement)
	encoded, err := EncodeElement(original)
	if err != nil {
		t.Fatalf("Failed to encode: %v", err)
	}

	// Decode it back
	reader := bytes.NewReader(encoded)
	decoded, err := DecodeElement(reader, stream)
	if err != nil {
		t.Fatalf("Failed to decode: %v", err)
	}

	// Verify type
	decodedNcd, ok := decoded.(*NewClassDesc)
	if !ok {
		t.Fatalf("Expected *NewClassDesc, got %T", decoded)
	}

	// Verify fields
	if decodedNcd.ClassName == nil || decodedNcd.ClassName.Contents != original.ClassName.Contents {
		t.Errorf("ClassName mismatch")
	}
	if decodedNcd.SerialVersion != original.SerialVersion {
		t.Errorf("SerialVersion mismatch: expected 0x%x, got 0x%x", original.SerialVersion, decodedNcd.SerialVersion)
	}
	if decodedNcd.Flags != original.Flags {
		t.Errorf("Flags mismatch: expected 0x%x, got 0x%x", original.Flags, decodedNcd.Flags)
	}
	if len(decodedNcd.Fields) != len(original.Fields) {
		t.Errorf("Fields count mismatch: expected %d, got %d", len(original.Fields), len(decodedNcd.Fields))
	}

	// Re-encode and verify bytes match
	reencoded, err := EncodeElement(decodedNcd)
	if err != nil {
		t.Fatalf("Failed to re-encode: %v", err)
	}

	if !bytes.Equal(encoded, reencoded) {
		t.Errorf("Re-encoded data doesn't match original")
		t.Errorf("Original length: %d, Re-encoded length: %d", len(encoded), len(reencoded))
		// Find first difference
		minLen := len(encoded)
		if len(reencoded) < minLen {
			minLen = len(reencoded)
		}
		for i := 0; i < minLen; i++ {
			if encoded[i] != reencoded[i] {
				t.Errorf("First difference at position %d: original=0x%02x, re-encoded=0x%02x", i, encoded[i], reencoded[i])
				break
			}
		}
	}
}

