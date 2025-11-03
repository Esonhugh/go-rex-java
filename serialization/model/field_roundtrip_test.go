package model

import (
	"bytes"
	"testing"
)

// TestFieldRoundTrip tests that Field can be decoded and encoded back to the same bytes
func TestFieldRoundTrip(t *testing.T) {
	tests := []struct {
		name      string
		fieldType ObjectType
		fieldName string
		typeDesc  string // For object/array types
	}{
		{"Byte", Byte, "value", ""},
		{"Char", Char, "ch", ""},
		{"Double", Double, "d", ""},
		{"Float", Float, "f", ""},
		{"Int", Int, "i", ""},
		{"Long", Long, "l", ""},
		{"Short", Short, "s", ""},
		{"Boolean", Boolean, "flag", ""},
		{"Object", Object, "obj", "Ljava/lang/String;"},
		{"Array", Array, "arr", "[I"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stream := NewStream()

			// Create original Field
			original := NewField(stream)
			original.Type = tt.fieldType
			original.Name = NewUtf(stream, tt.fieldName)
			if tt.typeDesc != "" {
				original.FieldType = NewUtf(stream, tt.typeDesc)
			}

			// Encode via ClassDesc context (Field is usually encoded as part of NewClassDesc)
			// But we can test Field.Encode() directly
			encoded, err := original.Encode()
			if err != nil {
				t.Fatalf("Failed to encode: %v", err)
			}

			// For round-trip, we need to decode it back
			// Field.Decode needs to know the type, so we'll create a minimal context
			reader := bytes.NewReader(encoded)
			decoded := NewField(stream)
			decoded.Type = tt.fieldType // Set type before decoding

			err = decoded.Decode(reader, stream)
			if err != nil {
				t.Fatalf("Failed to decode: %v", err)
			}

			// Verify fields
			if decoded.Type != original.Type {
				t.Errorf("Type mismatch: expected %v, got %v", original.Type, decoded.Type)
			}
			if decoded.Name == nil || decoded.Name.Contents != original.Name.Contents {
				t.Errorf("Name mismatch: expected %q, got %q", original.Name.Contents, getFieldName(decoded.Name))
			}
			if (original.FieldType == nil) != (decoded.FieldType == nil) {
				t.Errorf("FieldType presence mismatch")
			}
			if original.FieldType != nil && decoded.FieldType != nil {
				if original.FieldType.Contents != decoded.FieldType.Contents {
					t.Errorf("FieldType mismatch: expected %q, got %q", original.FieldType.Contents, decoded.FieldType.Contents)
				}
			}

			// Re-encode and verify bytes match
			reencoded, err := decoded.Encode()
			if err != nil {
				t.Fatalf("Failed to re-encode: %v", err)
			}

			if !bytes.Equal(encoded, reencoded) {
				t.Errorf("Re-encoded data doesn't match original")
				t.Errorf("Original: %x", encoded)
				t.Errorf("Re-encoded: %x", reencoded)
			}
		})
	}
}

func getFieldName(utf *Utf) string {
	if utf == nil {
		return ""
	}
	return utf.Contents
}

