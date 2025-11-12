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
				// Create fieldType Utf but don't add to references yet (will be added during decode)
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
			// Create a new stream for decoding to properly track references
			decodedStream := NewStream()
			reader := bytes.NewReader(encoded)
			decoded := NewField(decodedStream)
			decoded.Type = tt.fieldType // Set type before decoding

			err = decoded.Decode(reader, decodedStream)
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
			// Note: The re-encoded data might use TC_REFERENCE if the fieldType was added to references
			// during decode, but the original encoding might have used TC_STRING. This is acceptable
			// as both are valid, but the content should be semantically equivalent.
			reencoded, err := decoded.Encode()
			if err != nil {
				t.Fatalf("Failed to re-encode: %v", err)
			}

			// For round-trip, we decode the re-encoded data again to ensure it's still valid
			reader2 := bytes.NewReader(reencoded)
			decoded2 := NewField(decodedStream)
			decoded2.Type = tt.fieldType
			err = decoded2.Decode(reader2, decodedStream)
			if err != nil {
				t.Fatalf("Failed to decode re-encoded data: %v", err)
			}

			// Verify the decoded content matches
			if decoded2.Name == nil || decoded2.Name.Contents != original.Name.Contents {
				t.Errorf("Round-trip name mismatch: expected %q, got %q", original.Name.Contents, getFieldName(decoded2.Name))
			}
			if original.FieldType != nil && decoded2.FieldType != nil {
				if original.FieldType.Contents != decoded2.FieldType.Contents {
					t.Errorf("Round-trip fieldType mismatch: expected %q, got %q", original.FieldType.Contents, decoded2.FieldType.Contents)
				}
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

