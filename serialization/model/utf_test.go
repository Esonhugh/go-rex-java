package model

import (
	"bytes"
	"testing"
)

func TestNewUtf(t *testing.T) {
	content := "hello world"
	utf := NewUtf(nil, content)

	if utf.Length != uint16(len(content)) {
		t.Errorf("Expected length %d, got %d", len(content), utf.Length)
	}

	if utf.Contents != content {
		t.Errorf("Expected contents %q, got %q", content, utf.Contents)
	}
}

func TestUtfEncode(t *testing.T) {
	content := "hello"
	utf := NewUtf(nil, content)

	encoded, err := utf.Encode()
	if err != nil {
		t.Fatalf("Failed to encode UTF: %v", err)
	}

	// Check length (first 2 bytes, big endian)
	expectedLength := []byte{0x00, 0x05} // 5 bytes
	if !bytes.Equal(encoded[:2], expectedLength) {
		t.Errorf("Expected length %v, got %v", expectedLength, encoded[:2])
	}

	// Check content
	expectedContent := []byte("hello")
	if !bytes.Equal(encoded[2:], expectedContent) {
		t.Errorf("Expected content %v, got %v", expectedContent, encoded[2:])
	}
}

func TestUtfDecode(t *testing.T) {
	// Create test data: length (2 bytes) + content
	content := "test"
	data := make([]byte, 2+len(content))
	data[0] = 0x00 // length high byte
	data[1] = 0x04 // length low byte (4)
	copy(data[2:], content)

	reader := bytes.NewReader(data)
	utf := NewUtf(nil, "")

	err := utf.Decode(reader, nil)
	if err != nil {
		t.Fatalf("Failed to decode UTF: %v", err)
	}

	if utf.Length != 4 {
		t.Errorf("Expected length 4, got %d", utf.Length)
	}

	if utf.Contents != content {
		t.Errorf("Expected content %q, got %q", content, utf.Contents)
	}
}

func TestUtfString(t *testing.T) {
	content := "hello world"
	utf := NewUtf(nil, content)

	str := utf.String()
	if str != content {
		t.Errorf("Expected %q, got %q", content, str)
	}
}

func TestUtfEmptyString(t *testing.T) {
	utf := NewUtf(nil, "")

	if utf.Length != 0 {
		t.Errorf("Expected length 0, got %d", utf.Length)
	}

	if utf.Contents != "" {
		t.Errorf("Expected empty string, got %q", utf.Contents)
	}

	encoded, err := utf.Encode()
	if err != nil {
		t.Fatalf("Failed to encode empty UTF: %v", err)
	}

	// Should be just length (2 bytes of zeros)
	expected := []byte{0x00, 0x00}
	if !bytes.Equal(encoded, expected) {
		t.Errorf("Expected %v, got %v", expected, encoded)
	}
}

func TestUtfDecodeEmptyString(t *testing.T) {
	// Empty string: length = 0
	data := []byte{0x00, 0x00}
	reader := bytes.NewReader(data)
	utf := NewUtf(nil, "")

	err := utf.Decode(reader, nil)
	if err != nil {
		t.Fatalf("Failed to decode empty UTF: %v", err)
	}

	if utf.Length != 0 {
		t.Errorf("Expected length 0, got %d", utf.Length)
	}

	if utf.Contents != "" {
		t.Errorf("Expected empty string, got %q", utf.Contents)
	}
}
