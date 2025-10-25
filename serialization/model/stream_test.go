package model

import (
	"bytes"
	"testing"
)

func TestNewStream(t *testing.T) {
	stream := NewStream()

	if stream.Magic != 0xaced {
		t.Errorf("Expected magic 0xaced, got 0x%x", stream.Magic)
	}

	if stream.Version != 5 {
		t.Errorf("Expected version 5, got %d", stream.Version)
	}

	if stream.Contents == nil {
		t.Error("Expected contents to be initialized")
	}

	if stream.References == nil {
		t.Error("Expected references to be initialized")
	}
}

func TestStreamEncode(t *testing.T) {
	stream := NewStream()

	encoded, err := stream.Encode()
	if err != nil {
		t.Fatalf("Failed to encode stream: %v", err)
	}

	// Check magic number (first 2 bytes)
	expectedMagic := []byte{0xac, 0xed}
	if !bytes.Equal(encoded[:2], expectedMagic) {
		t.Errorf("Expected magic %v, got %v", expectedMagic, encoded[:2])
	}

	// Check version (next 2 bytes)
	expectedVersion := []byte{0x00, 0x05}
	if !bytes.Equal(encoded[2:4], expectedVersion) {
		t.Errorf("Expected version %v, got %v", expectedVersion, encoded[2:4])
	}
}

func TestStreamAddReference(t *testing.T) {
	stream := NewStream()
	utf := NewUtf(nil, "test")

	stream.AddReference(utf)

	if len(stream.References) != 1 {
		t.Errorf("Expected 1 reference, got %d", len(stream.References))
	}

	if stream.References[0] != utf {
		t.Error("Reference not added correctly")
	}
}

func TestStreamString(t *testing.T) {
	stream := NewStream()
	utf := NewUtf(nil, "test")
	stream.AddReference(utf)

	str := stream.String()

	if str == "" {
		t.Error("String representation should not be empty")
	}

	// Check that it contains expected elements
	if !contains(str, "@magic: 0xaced") {
		t.Error("String should contain magic number")
	}

	if !contains(str, "@version: 5") {
		t.Error("String should contain version")
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && s[:len(substr)] == substr ||
		len(s) > len(substr) && contains(s[1:], substr)
}
