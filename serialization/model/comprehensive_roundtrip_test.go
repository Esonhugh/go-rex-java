package model

import (
	"bytes"
	"testing"

	"github.com/esonhugh/go-rex-java/constants"
)

// TestComprehensiveRoundTrip tests that decode -> encode -> decode produces identical results
func TestComprehensiveRoundTrip(t *testing.T) {
	// Test with a simple object first
	t.Run("SimpleObject", func(t *testing.T) {
		// Create a simple stream with a NewObject
		stream := NewStream()
		
		// Create class description
		classDesc := NewClassDescInstance(stream)
		newClassDesc := NewNewClassDesc(stream)
		newClassDesc.ClassName = NewUtf(stream, "TestClass")
		newClassDesc.SerialVersion = 0x1234567890ABCDEF
		newClassDesc.Flags = constants.SC_SERIALIZABLE
		
		// Add an int field
		field := NewField(stream)
		field.Type = Int
		field.Name = NewUtf(stream, "value")
		newClassDesc.Fields = []*Field{field}
		
		newClassDesc.ClassAnnotation = NewAnnotation(stream)
		newClassDesc.ClassAnnotation.Contents = []Element{NewEndBlockData(stream)}
		newClassDesc.SuperClass = NewClassDescInstance(stream)
		newClassDesc.SuperClass.Description = NewNullReference(stream)
		classDesc.Description = newClassDesc
		
		// Create object
		obj := NewNewObject(stream)
		obj.ClassDesc = classDesc
		obj.ClassData = []*PrimitiveValue{
			NewPrimitiveValue(Int, int32(42)),
		}
		
		stream.Contents = []Element{obj}
		
		// Encode
		encoded1, err := stream.Encode()
		if err != nil {
			t.Fatalf("Failed to encode: %v", err)
		}
		
		// Decode
		reader1 := bytes.NewReader(encoded1)
		decodedStream := NewStream()
		if err := decodedStream.Decode(reader1); err != nil {
			t.Fatalf("Failed to decode: %v", err)
		}
		
		// Re-encode
		encoded2, err := decodedStream.Encode()
		if err != nil {
			t.Fatalf("Failed to re-encode: %v", err)
		}
		
		// Compare
		if !bytes.Equal(encoded1, encoded2) {
			t.Errorf("Round-trip failed: lengths differ (first=%d, second=%d)", len(encoded1), len(encoded2))
			// Find first difference
			minLen := len(encoded1)
			if len(encoded2) < minLen {
				minLen = len(encoded2)
			}
			for i := 0; i < minLen; i++ {
				if encoded1[i] != encoded2[i] {
					t.Errorf("First difference at position %d: 0x%02x vs 0x%02x", i, encoded1[i], encoded2[i])
					break
				}
			}
		}
	})
	
	// Test with object containing string field
	t.Run("ObjectWithStringField", func(t *testing.T) {
		stream := NewStream()
		
		// Create class with string field
		classDesc := NewClassDescInstance(stream)
		newClassDesc := NewNewClassDesc(stream)
		newClassDesc.ClassName = NewUtf(stream, "StringHolder")
		newClassDesc.SerialVersion = 0xABCDEF1234567890
		newClassDesc.Flags = constants.SC_SERIALIZABLE
		
		// Add string field
		field := NewField(stream)
		field.Type = Object
		field.Name = NewUtf(stream, "str")
		strType := NewUtf(stream, "Ljava/lang/String;")
		stream.AddReference(strType) // Add to references first
		field.FieldType = strType
		newClassDesc.Fields = []*Field{field}
		
		newClassDesc.ClassAnnotation = NewAnnotation(stream)
		newClassDesc.ClassAnnotation.Contents = []Element{NewEndBlockData(stream)}
		newClassDesc.SuperClass = NewClassDescInstance(stream)
		newClassDesc.SuperClass.Description = NewNullReference(stream)
		classDesc.Description = newClassDesc
		
		// Create object with string value
		obj := NewNewObject(stream)
		obj.ClassDesc = classDesc
		strValue := NewUtf(stream, "Hello World")
		stream.AddReference(strValue) // Add to references
		obj.ClassData = []*PrimitiveValue{
			NewPrimitiveValue(Object, strValue),
		}
		
		stream.Contents = []Element{obj}
		
		// Encode
		encoded1, err := stream.Encode()
		if err != nil {
			t.Fatalf("Failed to encode: %v", err)
		}
		
		// Decode
		reader1 := bytes.NewReader(encoded1)
		decodedStream := NewStream()
		if err := decodedStream.Decode(reader1); err != nil {
			t.Fatalf("Failed to decode: %v", err)
		}
		
		// Re-encode
		encoded2, err := decodedStream.Encode()
		if err != nil {
			t.Fatalf("Failed to re-encode: %v", err)
		}
		
		// Compare
		if !bytes.Equal(encoded1, encoded2) {
			t.Errorf("Round-trip failed: lengths differ (first=%d, second=%d)", len(encoded1), len(encoded2))
		}
	})
	
	// Test with nested object
	t.Run("NestedObject", func(t *testing.T) {
		stream := NewStream()
		
		// Inner class
		innerClassDesc := NewClassDescInstance(stream)
		innerNewClassDesc := NewNewClassDesc(stream)
		innerNewClassDesc.ClassName = NewUtf(stream, "Inner")
		innerNewClassDesc.SerialVersion = 0x1111111111111111
		innerNewClassDesc.Flags = constants.SC_SERIALIZABLE
		innerNewClassDesc.Fields = []*Field{}
		innerNewClassDesc.ClassAnnotation = NewAnnotation(stream)
		innerNewClassDesc.ClassAnnotation.Contents = []Element{NewEndBlockData(stream)}
		innerNewClassDesc.SuperClass = NewClassDescInstance(stream)
		innerNewClassDesc.SuperClass.Description = NewNullReference(stream)
		innerClassDesc.Description = innerNewClassDesc
		
		// Inner object
		innerObj := NewNewObject(stream)
		innerObj.ClassDesc = innerClassDesc
		innerObj.ClassData = []*PrimitiveValue{}
		
		// Outer class with Object field
		outerClassDesc := NewClassDescInstance(stream)
		outerNewClassDesc := NewNewClassDesc(stream)
		outerNewClassDesc.ClassName = NewUtf(stream, "Outer")
		outerNewClassDesc.SerialVersion = 0x2222222222222222
		outerNewClassDesc.Flags = constants.SC_SERIALIZABLE
		
		field := NewField(stream)
		field.Type = Object
		field.Name = NewUtf(stream, "inner")
		field.FieldType = NewUtf(stream, "LInner;")
		outerNewClassDesc.Fields = []*Field{field}
		outerNewClassDesc.ClassAnnotation = NewAnnotation(stream)
		outerNewClassDesc.ClassAnnotation.Contents = []Element{NewEndBlockData(stream)}
		outerNewClassDesc.SuperClass = NewClassDescInstance(stream)
		outerNewClassDesc.SuperClass.Description = NewNullReference(stream)
		outerClassDesc.Description = outerNewClassDesc
		
		// Outer object
		outerObj := NewNewObject(stream)
		outerObj.ClassDesc = outerClassDesc
		outerObj.ClassData = []*PrimitiveValue{
			NewPrimitiveValue(Object, innerObj),
		}
		
		stream.Contents = []Element{outerObj}
		
		// Encode -> Decode -> Encode
		encoded1, err := stream.Encode()
		if err != nil {
			t.Fatalf("Failed to encode: %v", err)
		}
		
		reader1 := bytes.NewReader(encoded1)
		decodedStream := NewStream()
		if err := decodedStream.Decode(reader1); err != nil {
			t.Fatalf("Failed to decode: %v", err)
		}
		
		encoded2, err := decodedStream.Encode()
		if err != nil {
			t.Fatalf("Failed to re-encode: %v", err)
		}
		
		if !bytes.Equal(encoded1, encoded2) {
			t.Errorf("Round-trip failed for nested object")
		}
	})
}

// TestReferenceHandling tests that references are correctly used during encoding
func TestReferenceHandling(t *testing.T) {
	stream := NewStream()
	
	// Create a string that will be referenced multiple times
	sharedStr := NewUtf(stream, "shared")
	stream.AddReference(sharedStr)
	
	// Create class with field type that uses the shared string
	classDesc := NewClassDescInstance(stream)
	newClassDesc := NewNewClassDesc(stream)
	newClassDesc.ClassName = NewUtf(stream, "TestClass")
	newClassDesc.SerialVersion = 0x1234567890ABCDEF
	newClassDesc.Flags = constants.SC_SERIALIZABLE
	
	// Field type should use TC_REFERENCE since sharedStr is in references
	field := NewField(stream)
	field.Type = Object
	field.Name = NewUtf(stream, "field")
	field.FieldType = sharedStr // Use the shared string
	newClassDesc.Fields = []*Field{field}
	
	newClassDesc.ClassAnnotation = NewAnnotation(stream)
	newClassDesc.ClassAnnotation.Contents = []Element{NewEndBlockData(stream)}
	newClassDesc.SuperClass = NewClassDescInstance(stream)
	newClassDesc.SuperClass.Description = NewNullReference(stream)
	classDesc.Description = newClassDesc
	
	obj := NewNewObject(stream)
	obj.ClassDesc = classDesc
	obj.ClassData = []*PrimitiveValue{
		NewPrimitiveValue(Object, sharedStr), // Also use shared string as value
	}
	
	stream.Contents = []Element{obj}
	
	// Encode
	encoded, err := stream.Encode()
	if err != nil {
		t.Fatalf("Failed to encode: %v", err)
	}
	
	// Decode and verify
	reader := bytes.NewReader(encoded)
	decodedStream := NewStream()
	if err := decodedStream.Decode(reader); err != nil {
		t.Fatalf("Failed to decode: %v", err)
	}
	
	// Verify references were used
	if len(decodedStream.References) == 0 {
		t.Error("Expected references to be populated")
	}
	
	// Re-encode and verify round-trip
	reencoded, err := decodedStream.Encode()
	if err != nil {
		t.Fatalf("Failed to re-encode: %v", err)
	}
	
	if !bytes.Equal(encoded, reencoded) {
		t.Errorf("Round-trip failed for reference handling")
	}
}

