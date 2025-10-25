package model

import (
	"bytes"
	"testing"
)

func TestNewClassDesc(t *testing.T) {
	classDesc := NewClassDescInstance(nil)

	if classDesc.Description != nil {
		t.Error("Expected description to be nil")
	}
}

func TestClassDescString(t *testing.T) {
	classDesc := NewClassDescInstance(nil)

	str := classDesc.String()
	expected := "ClassDesc(nil)"
	if str != expected {
		t.Errorf("Expected %q, got %q", expected, str)
	}
}

func TestClassDescStringWithDescription(t *testing.T) {
	classDesc := NewClassDescInstance(nil)
	classDesc.Description = NewUtf(nil, "test")

	str := classDesc.String()
	if str == "" {
		t.Error("Expected non-empty string")
	}
}

func TestClassDescDecodeNullReference(t *testing.T) {
	// TC_NULL
	data := []byte{0x70}
	reader := bytes.NewReader(data)
	classDesc := NewClassDescInstance(nil)

	err := classDesc.Decode(reader, nil)
	if err != nil {
		t.Fatalf("Failed to decode ClassDesc: %v", err)
	}

	if classDesc.Description == nil {
		t.Error("Expected description to be set")
	}

	_, ok := classDesc.Description.(*NullReference)
	if !ok {
		t.Error("Expected description to be NullReference")
	}
}

func TestClassDescDecodeInvalidType(t *testing.T) {
	// TC_STRING (invalid for ClassDesc)
	data := []byte{0x74, 0x00, 0x04, 't', 'e', 's', 't'}
	reader := bytes.NewReader(data)
	classDesc := NewClassDescInstance(nil)

	err := classDesc.Decode(reader, nil)
	if err == nil {
		t.Error("Expected error for invalid content type")
	}
}

func TestClassDescEncodeNullReference(t *testing.T) {
	classDesc := NewClassDescInstance(nil)
	classDesc.Description = NewNullReference(nil)

	encoded, err := classDesc.Encode()
	if err != nil {
		t.Fatalf("Failed to encode ClassDesc: %v", err)
	}

	// Should be just the TC_NULL opcode
	expected := []byte{0x70}
	if !bytes.Equal(encoded, expected) {
		t.Errorf("Expected %v, got %v", expected, encoded)
	}
}

func TestClassDescEncodeNilDescription(t *testing.T) {
	classDesc := NewClassDescInstance(nil)

	_, err := classDesc.Encode()
	if err == nil {
		t.Error("Expected error for nil description")
	}
}

func TestClassDescEncodeInvalidType(t *testing.T) {
	classDesc := NewClassDescInstance(nil)
	classDesc.Description = NewUtf(nil, "test") // Invalid for ClassDesc

	_, err := classDesc.Encode()
	if err == nil {
		t.Error("Expected error for invalid description type")
	}
}
