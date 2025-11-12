package model

import (
	"encoding/json"
	"github.com/esonhugh/go-rex-java/constants"
	"io"
)

// Field represents a field description in Java serialization
type Field struct {
	*BaseElement
	Type      ObjectType
	Name      *Utf
	FieldType *Utf
}

// NewField creates a new Field instance
func NewField(stream *Stream) *Field {
	return &Field{
		BaseElement: NewBaseElement(stream),
		Type:        "",
		Name:        nil,
		FieldType:   nil,
	}
}

// Decode deserializes a Field from the given reader
func (f *Field) Decode(reader io.Reader, stream *Stream) error {
	// Read type code
	typeCode := make([]byte, 1)
	if _, err := io.ReadFull(reader, typeCode); err != nil {
		return &DecodeError{Message: "failed to read field type code"}
	}

	// Validate type code
	typeCodes := map[byte]ObjectType{
		constants.TYPE_BYTE:    Byte,
		constants.TYPE_CHAR:    Char,
		constants.TYPE_DOUBLE:  Double,
		constants.TYPE_FLOAT:   Float,
		constants.TYPE_INT:     Int,
		constants.TYPE_LONG:    Long,
		constants.TYPE_SHORT:   Short,
		constants.TYPE_BOOLEAN: Boolean,
		constants.TYPE_ARRAY:   Array,
		constants.TYPE_OBJECT:  Object,
	}
	if typeName, exists := typeCodes[typeCode[0]]; exists {
		f.Type = typeName
	} else {
		return &DecodeError{Message: "invalid field type code"}
	}

	f.Stream = stream

	// Decode name
	f.Name = NewUtf(stream, "")
	if err := f.Name.Decode(reader, stream); err != nil {
		// Be tolerant: if we can't decode name, use empty string
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			f.Name.Contents = ""
			f.Name.Length = 0
		} else {
			return err
		}
	}

	// Decode field type if it's an object type or array type
	// Field type can be TC_STRING (Utf) or TC_REFERENCE (Reference)
	// Both Object ('L') and Array ('[') types have field_type
	if f.IsObject() || f.Type == Array {
		fieldType, err := DecodeElement(reader, stream)
		if err != nil {
			// Be tolerant: if we can't decode field type, use a placeholder
			if err == io.EOF || err == io.ErrUnexpectedEOF {
				f.FieldType = NewUtf(stream, "")
				return nil
			}
			return err
		}

		if utf, ok := fieldType.(*Utf); ok {
			// Check if this Utf already exists in stream references (by content)
			// If so, use the one from references to ensure correct reference matching
			if stream != nil {
				for _, ref := range stream.References {
					if refUtf, ok := ref.(*Utf); ok && utf.Contents == refUtf.Contents {
						f.FieldType = refUtf // Use the one from references
						return nil
					}
				}
			}
			f.FieldType = utf
		} else if ref, ok := fieldType.(*Reference); ok {
			// If it's a reference, resolve it
			if stream != nil {
				refIndex := ref.Handle - constants.BASE_WIRE_HANDLE
				if refIndex < uint32(len(stream.References)) {
					switch refElem := stream.References[refIndex].(type) {
					case *Utf:
						f.FieldType = refElem
					default:
						// Be tolerant: use string representation when reference is not Utf
						f.FieldType = NewUtf(stream, refElem.String())
					}
				} else {
					return &DecodeError{Message: "invalid reference handle for field type"}
				}
			} else {
				return &DecodeError{Message: "cannot resolve field type reference without stream"}
			}
		} else {
			// Be tolerant: if not Utf/Reference, still capture a readable type string
			if elem, ok := fieldType.(Element); ok {
				f.FieldType = NewUtf(stream, elem.String())
			} else {
				return &DecodeError{Message: "field type is not a UTF string or Reference"}
			}
		}
	}

	return nil
}

// Encode serializes the Field to bytes
func (f *Field) Encode() ([]byte, error) {
	return f.EncodeWithContext(nil)
}

// EncodeWithContext serializes the Field with a shared encode context
func (f *Field) EncodeWithContext(ctx *EncodeContext) ([]byte, error) {
	if f.Name == nil {
		return nil, &EncodeError{Message: "field name is nil"}
	}

	if !f.IsTypeValid() {
		return nil, &EncodeError{Message: "invalid field type"}
	}

	encoded := make([]byte, 0, 1024)

	// Find type code
	typeCodes := map[byte]ObjectType{
		'B': Byte, 'C': Char, 'D': Double, 'F': Float,
		'I': Int, 'J': Long, 'S': Short, 'Z': Boolean,
		'[': Array, 'L': Object,
	}
	var typeCode byte
	for code, typeName := range typeCodes {
		if typeName == f.Type {
			typeCode = code
			break
		}
	}
	encoded = append(encoded, typeCode)

	// Encode name
	nameBytes, err := f.Name.Encode()
	if err != nil {
		return nil, err
	}
	encoded = append(encoded, nameBytes...)

	// Encode field type if it's an object type
	if f.IsObject() && f.FieldType != nil {
		// Use EncodeElementWithContext to check if fieldType should use TC_REFERENCE
		if ctx != nil {
			fieldTypeBytes, err := EncodeElementWithContext(f.FieldType, ctx)
			if err != nil {
				return nil, err
			}
			encoded = append(encoded, fieldTypeBytes...)
		} else {
			fieldTypeBytes, err := EncodeElementWithReferences(f.FieldType, f.Stream)
			if err != nil {
				return nil, err
			}
			encoded = append(encoded, fieldTypeBytes...)
		}
	}

	return encoded, nil
}

// IsTypeValid checks if the field type is valid
func (f *Field) IsTypeValid() bool {
	typeCodes := map[byte]ObjectType{
		'B': Byte, 'C': Char, 'D': Double, 'F': Float,
		'I': Int, 'J': Long, 'S': Short, 'Z': Boolean,
		'[': Array, 'L': Object,
	}
	for _, typeName := range typeCodes {
		if typeName == f.Type {
			return true
		}
	}
	return false
}

// IsPrimitive checks if the field type is primitive
func (f *Field) IsPrimitive() bool {
	return f.Type.IsPrimitive()
}

// IsObject checks if the field type is an object
func (f *Field) IsObject() bool {
	return f.Type.IsObject()
}

// String returns a string representation of the Field
func (f *Field) String() string {
	if f.Name == nil {
		return "Field(nil)"
	}

	result := f.Name.String() + " "
	if f.IsPrimitive() {
		result += "(" + f.Type.String() + ")"
	} else if f.FieldType != nil {
		result += "(" + f.FieldType.String() + ")"
	}

	return result
}

// marshalField marshals a Field to JSON-friendly format
func marshalField(f *Field) interface{} {
	result := map[string]interface{}{
		"type": f.Type.String(),
	}

	if f.Name != nil {
		result["name"] = f.Name.String()
	}
	if f.FieldType != nil {
		result["field_type"] = f.FieldType.String()
	}

	return result
}

// MarshalJSON marshals Field to JSON
func (f *Field) MarshalJSON() ([]byte, error) {
	return json.Marshal(marshalField(f))
}
