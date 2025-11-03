package model

import (
	"bytes"
	"testing"
)

// TestNewEnumRoundTrip tests that NewEnum can be decoded and encoded back to the same bytes
func TestNewEnumRoundTrip(t *testing.T) {
	stream := NewStream()

	// Create a complete NewEnum
	original := NewNewEnum(stream)

	// Set enum class description
	original.EnumClassDesc = NewClassDescInstance(stream)
	enumClassDesc := NewNewClassDesc(stream)
	enumClassDesc.ClassName = NewUtf(stream, "TestEnum")
	enumClassDesc.SerialVersion = 0xABCDEF1234567890
	enumClassDesc.Flags = 0x12 // SC_ENUM
	enumClassDesc.Fields = []*Field{}
	enumClassDesc.ClassAnnotation = NewAnnotation(stream)
	enumClassDesc.ClassAnnotation.Contents = []Element{NewEndBlockData(stream)}
	enumClassDesc.SuperClass = NewClassDescInstance(stream)
	enumClassDesc.SuperClass.Description = NewNullReference(stream)
	original.EnumClassDesc.Description = enumClassDesc

	// Set enum constant name
	original.EnumConstantName = NewUtf(stream, "VALUE1")

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

	decodedEnum, ok := decoded.(*NewEnum)
	if !ok {
		t.Fatalf("Expected *NewEnum, got %T", decoded)
	}

	// Re-encode and verify
	reencoded, err := EncodeElement(decodedEnum)
	if err != nil {
		t.Fatalf("Failed to re-encode: %v", err)
	}

	if !bytes.Equal(encoded, reencoded) {
		t.Errorf("Re-encoded data doesn't match original")
	}
}

