package model

import (
	"bytes"
	"testing"
)

// TestProxyClassDescRoundTrip tests that ProxyClassDesc can be decoded and encoded back to the same bytes
func TestProxyClassDescRoundTrip(t *testing.T) {
	stream := NewStream()

	// Create a complete ProxyClassDesc
	original := NewProxyClassDesc(stream)

	// Add interfaces
	original.Interfaces = []*Utf{
		NewUtf(stream, "java.io.Serializable"),
		NewUtf(stream, "java.lang.Runnable"),
	}

	// Add class annotation
	original.ClassAnnotation = NewAnnotation(stream)
	original.ClassAnnotation.Contents = []Element{NewEndBlockData(stream)}

	// Add super class
	original.SuperClass = NewClassDescInstance(stream)
	original.SuperClass.Description = NewNullReference(stream)

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

	decodedProxy, ok := decoded.(*ProxyClassDesc)
	if !ok {
		t.Fatalf("Expected *ProxyClassDesc, got %T", decoded)
	}

	// Verify interfaces
	if len(decodedProxy.Interfaces) != len(original.Interfaces) {
		t.Errorf("Interfaces count mismatch: expected %d, got %d", len(original.Interfaces), len(decodedProxy.Interfaces))
	}

	// Re-encode and verify
	reencoded, err := EncodeElement(decodedProxy)
	if err != nil {
		t.Fatalf("Failed to re-encode: %v", err)
	}

	if !bytes.Equal(encoded, reencoded) {
		t.Errorf("Re-encoded data doesn't match original")
		t.Errorf("Original length: %d, Re-encoded length: %d", len(encoded), len(reencoded))
	}
}

