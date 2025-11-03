package model

import (
	"bytes"
	"testing"
)

// TestNewClassRoundTrip tests that NewClass can be decoded and encoded back to the same bytes
func TestNewClassRoundTrip(t *testing.T) {
	stream := NewStream()

	// Create a complete NewClass
	original := NewNewClass(stream)

	// Set class description
	original.ClassDescription = NewClassDescInstance(stream)
	classDesc := NewNewClassDesc(stream)
	classDesc.ClassName = NewUtf(stream, "TestClass")
	classDesc.SerialVersion = 0x1234567890ABCDEF
	classDesc.Flags = 0x02
	classDesc.Fields = []*Field{}
	classDesc.ClassAnnotation = NewAnnotation(stream)
	classDesc.ClassAnnotation.Contents = []Element{NewEndBlockData(stream)}
	classDesc.SuperClass = NewClassDescInstance(stream)
	classDesc.SuperClass.Description = NewNullReference(stream)
	original.ClassDescription.Description = classDesc

	// Encode
	encoded, err := EncodeElement(original)
	if err != nil {
		t.Fatalf("Failed to encode: %v", err)
	}

	// Decode back
	reader := bytes.NewReader(encoded)
	decoded, err := DecodeElement(reader, stream)
	if err != nil {
		t.Fatalf("Failed to decode: %v", err)
	}

	decodedClass, ok := decoded.(*NewClass)
	if !ok {
		t.Fatalf("Expected *NewClass, got %T", decoded)
	}

	// Re-encode and verify
	reencoded, err := EncodeElement(decodedClass)
	if err != nil {
		t.Fatalf("Failed to re-encode: %v", err)
	}

	if !bytes.Equal(encoded, reencoded) {
		t.Errorf("Re-encoded data doesn't match original")
	}
}

