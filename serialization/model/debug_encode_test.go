package model

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/esonhugh/go-rex-java/constants"
)

func TestDebugEncode(t *testing.T) {
	stream := NewStream()
	
	// Create class description
	classDesc := NewClassDescInstance(stream)
	newClassDesc := NewNewClassDesc(stream)
	newClassDesc.ClassName = NewUtf(stream, "TestClass")
	newClassDesc.SerialVersion = 0x1234567890ABCDEF
	newClassDesc.Flags = constants.SC_SERIALIZABLE
	newClassDesc.Fields = []*Field{}
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
	
	fmt.Printf("Encoded length: %d\n", len(encoded1))
	fmt.Printf("Encoded hex: %s\n", hex.EncodeToString(encoded1))
	
	// Check position 30
	if len(encoded1) > 30 {
		fmt.Printf("Position 30: 0x%02x\n", encoded1[30])
	}
	
	// Decode
	reader1 := bytes.NewReader(encoded1)
	decodedStream := NewStream()
	if err := decodedStream.Decode(reader1); err != nil {
		t.Fatalf("Failed to decode: %v", err)
	}
	
	// Debug: Check decoded contents
	if len(decodedStream.Contents) > 0 {
		if no, ok := decodedStream.Contents[0].(*NewObject); ok {
			fmt.Printf("Decoded ClassData count: %d\n", len(no.ClassData))
			if len(no.ClassData) > 0 {
				fmt.Printf("First ClassData: Type=%v, Value=%v\n", no.ClassData[0].Type, no.ClassData[0].Value)
			}
		}
	}
	
	// Re-encode
	encoded2, err := decodedStream.Encode()
	if err != nil {
		t.Fatalf("Failed to re-encode: %v", err)
	}
	
	fmt.Printf("Re-encoded length: %d\n", len(encoded2))
	fmt.Printf("Re-encoded hex: %s\n", hex.EncodeToString(encoded2))
	
	// Check position 30
	if len(encoded2) > 30 {
		fmt.Printf("Position 30: 0x%02x\n", encoded2[30])
	}
	
	// Compare
	if !bytes.Equal(encoded1, encoded2) {
		t.Errorf("Round-trip failed")
		for i := 0; i < len(encoded1) && i < len(encoded2); i++ {
			if encoded1[i] != encoded2[i] {
				t.Errorf("First difference at position %d: 0x%02x vs 0x%02x", i, encoded1[i], encoded2[i])
				break
			}
		}
	}
}

