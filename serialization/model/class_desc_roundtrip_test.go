package model

import (
	"bytes"
	"testing"

	"github.com/esonhugh/go-rex-java/constants"
)

// TestClassDescRoundTrip tests that ClassDesc can be decoded and encoded back to the same bytes
func TestClassDescRoundTrip(t *testing.T) {
	stream := NewStream()

	tests := []struct {
		name        string
		description Element
	}{
		{"WithNewClassDesc", func() Element {
			ncd := NewNewClassDesc(stream)
			ncd.ClassName = NewUtf(stream, "TestClass")
			ncd.SerialVersion = 0x1234567890ABCDEF
			ncd.Flags = 0x02
			ncd.Fields = []*Field{}
			ncd.ClassAnnotation = NewAnnotation(stream)
			ncd.ClassAnnotation.Contents = []Element{NewEndBlockData(stream)}
			ncd.SuperClass = NewClassDescInstance(stream)
			ncd.SuperClass.Description = NewNullReference(stream)
			return ncd
		}()},
		{"WithNullReference", NewNullReference(stream)},
		{"WithReference", func() Element {
			// Add an element to reference
			utf := NewUtf(stream, "referenced")
			stream.AddReference(utf)
			return NewReference(stream, constants.BASE_WIRE_HANDLE)
		}()},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create ClassDesc
			original := NewClassDescInstance(stream)
			original.Description = tt.description

			// Encode (ClassDesc.Encode() returns opcode + description)
			encoded, err := original.Encode()
			if err != nil {
				t.Fatalf("Failed to encode: %v", err)
			}

			// Decode back
			reader := bytes.NewReader(encoded)
			decoded, err := DecodeElement(reader, stream)
			if err != nil {
				t.Fatalf("Failed to decode: %v", err)
			}

			// Verify we got a valid description element
			_, ok1 := decoded.(*NewClassDesc)
			_, ok2 := decoded.(*NullReference)
			_, ok3 := decoded.(*Reference)
			if !ok1 && !ok2 && !ok3 {
				t.Fatalf("Expected NewClassDesc/NullReference/Reference, got %T", decoded)
			}

			// Create ClassDesc from decoded element
			decodedClassDesc := NewClassDescInstance(stream)
			decodedClassDesc.Description = decoded

			// Re-encode and verify
			reencoded, err := decodedClassDesc.Encode()
			if err != nil {
				t.Fatalf("Failed to re-encode: %v", err)
			}

			if !bytes.Equal(encoded, reencoded) {
				t.Errorf("Re-encoded data doesn't match original")
				t.Errorf("Original length: %d, Re-encoded length: %d", len(encoded), len(reencoded))
			}
		})
	}
}

