package model

import (
	"bytes"
	"testing"

	"github.com/esonhugh/go-rex-java/constants"
)

// TestNewObjectRoundTrip tests that NewObject can be decoded and encoded back to the same bytes
func TestNewObjectRoundTrip(t *testing.T) {
	stream := NewStream()

	// Create a complete NewObject with class description
	original := NewNewObject(stream)

	// Create ClassDesc with NewClassDesc
	classDesc := NewClassDescInstance(stream)
	newClassDesc := NewNewClassDesc(stream)
	newClassDesc.ClassName = NewUtf(stream, "TestClass")
	newClassDesc.SerialVersion = 0x1234567890ABCDEF
	newClassDesc.Flags = constants.SC_SERIALIZABLE

	// Add a field
	field := NewField(stream)
	field.Type = Int
	field.Name = NewUtf(stream, "value")
	newClassDesc.Fields = []*Field{field}

	// Add annotation
	newClassDesc.ClassAnnotation = NewAnnotation(stream)
	newClassDesc.ClassAnnotation.Contents = []Element{NewEndBlockData(stream)}

	// Add super class
	newClassDesc.SuperClass = NewClassDescInstance(stream)
	newClassDesc.SuperClass.Description = NewNullReference(stream)

	classDesc.Description = newClassDesc
	original.ClassDesc = classDesc

	// Add class data (primitive int value)
	original.ClassData = []*PrimitiveValue{
		NewPrimitiveValue(Int, int32(42)),
	}

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
	decodedObj, ok := decoded.(*NewObject)
	if !ok {
		t.Fatalf("Expected *NewObject, got %T", decoded)
	}

	// Verify class description
	if decodedObj.ClassDesc == nil {
		t.Fatal("ClassDesc is nil")
	}

	// Verify class data
	if len(decodedObj.ClassData) != len(original.ClassData) {
		t.Errorf("ClassData length mismatch: expected %d, got %d", len(original.ClassData), len(decodedObj.ClassData))
	}

	// Re-encode and verify bytes match
	reencoded, err := EncodeElement(decodedObj)
	if err != nil {
		t.Fatalf("Failed to re-encode: %v", err)
	}

	if !bytes.Equal(encoded, reencoded) {
		t.Errorf("Re-encoded data doesn't match original")
		t.Errorf("Original length: %d, Re-encoded length: %d", len(encoded), len(reencoded))
	}
}

// TestNewObjectRoundTripWithStringField tests NewObject with object type field
func TestNewObjectRoundTripWithStringField(t *testing.T) {
	stream := NewStream()

	// Create NewObject with String field
	original := NewNewObject(stream)

	classDesc := NewClassDescInstance(stream)
	newClassDesc := NewNewClassDesc(stream)
	newClassDesc.ClassName = NewUtf(stream, "StringHolder")
	newClassDesc.SerialVersion = 0xABCDEF1234567890
	newClassDesc.Flags = constants.SC_SERIALIZABLE

	// Add object field
	field := NewField(stream)
	field.Type = Object
	field.Name = NewUtf(stream, "str")
	field.FieldType = NewUtf(stream, "Ljava/lang/String;")
	newClassDesc.Fields = []*Field{field}

	// Add annotation
	newClassDesc.ClassAnnotation = NewAnnotation(stream)
	newClassDesc.ClassAnnotation.Contents = []Element{NewEndBlockData(stream)}

	// Add super class
	newClassDesc.SuperClass = NewClassDescInstance(stream)
	newClassDesc.SuperClass.Description = NewNullReference(stream)

	classDesc.Description = newClassDesc
	original.ClassDesc = classDesc

	// Add class data (UTF string)
	strUtf := NewUtf(stream, "Hello World")
	original.ClassData = []*PrimitiveValue{
		NewPrimitiveValue(Object, strUtf),
	}

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

	decodedObj, ok := decoded.(*NewObject)
	if !ok {
		t.Fatalf("Expected *NewObject, got %T", decoded)
	}

	// Re-encode and verify
	reencoded, err := EncodeElement(decodedObj)
	if err != nil {
		t.Fatalf("Failed to re-encode: %v", err)
	}

	if !bytes.Equal(encoded, reencoded) {
		t.Errorf("Re-encoded data doesn't match original")
	}
}

