package model

import (
	"bytes"
	"testing"
)

// TestNewArrayRoundTrip tests that NewArray can be decoded and encoded back to the same bytes
func TestNewArrayRoundTrip(t *testing.T) {
	stream := NewStream()

	// Test byte array
	t.Run("ByteArray", func(t *testing.T) {
		original := NewNewArray(stream)
		original.Type = "byte"

		// Set array description
		original.ArrayDescription = NewClassDescInstance(stream)
		arrClassDesc := NewNewClassDesc(stream)
		arrClassDesc.ClassName = NewUtf(stream, "[B")
		arrClassDesc.SerialVersion = 0
		arrClassDesc.Flags = 0
		arrClassDesc.Fields = []*Field{}
		arrClassDesc.ClassAnnotation = NewAnnotation(stream)
		arrClassDesc.ClassAnnotation.Contents = []Element{NewEndBlockData(stream)}
		arrClassDesc.SuperClass = NewClassDescInstance(stream)
		arrClassDesc.SuperClass.Description = NewNullReference(stream)
		original.ArrayDescription.Description = arrClassDesc

		// Add byte values
		original.Values = []interface{}{int8(1), int8(2), int8(3), int8(4)}

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

		decodedArr, ok := decoded.(*NewArray)
		if !ok {
			t.Fatalf("Expected *NewArray, got %T", decoded)
		}

		// Verify values
		if len(decodedArr.Values) != len(original.Values) {
			t.Errorf("Values length mismatch: expected %d, got %d", len(original.Values), len(decodedArr.Values))
		}

		// Re-encode and verify
		reencoded, err := EncodeElement(decodedArr)
		if err != nil {
			t.Fatalf("Failed to re-encode: %v", err)
		}

		if !bytes.Equal(encoded, reencoded) {
			t.Errorf("Re-encoded data doesn't match original")
		}
	})

	// Test int array
	t.Run("IntArray", func(t *testing.T) {
		original := NewNewArray(stream)
		original.Type = "int"

		original.ArrayDescription = NewClassDescInstance(stream)
		arrClassDesc := NewNewClassDesc(stream)
		arrClassDesc.ClassName = NewUtf(stream, "[I")
		arrClassDesc.SerialVersion = 0
		arrClassDesc.Flags = 0
		arrClassDesc.Fields = []*Field{}
		arrClassDesc.ClassAnnotation = NewAnnotation(stream)
		arrClassDesc.ClassAnnotation.Contents = []Element{NewEndBlockData(stream)}
		arrClassDesc.SuperClass = NewClassDescInstance(stream)
		arrClassDesc.SuperClass.Description = NewNullReference(stream)
		original.ArrayDescription.Description = arrClassDesc

		original.Values = []interface{}{int32(100), int32(200), int32(300)}

		encoded, err := EncodeElement(original)
		if err != nil {
			t.Fatalf("Failed to encode: %v", err)
		}

		reader := bytes.NewReader(encoded)
		decoded, err := DecodeElement(reader, stream)
		if err != nil {
			t.Fatalf("Failed to decode: %v", err)
		}

		decodedArr, ok := decoded.(*NewArray)
		if !ok {
			t.Fatalf("Expected *NewArray, got %T", decoded)
		}

		reencoded, err := EncodeElement(decodedArr)
		if err != nil {
			t.Fatalf("Failed to re-encode: %v", err)
		}

		if !bytes.Equal(encoded, reencoded) {
			t.Errorf("Re-encoded data doesn't match original")
		}
	})
}

