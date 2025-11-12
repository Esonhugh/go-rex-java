package model

import (
	"encoding/binary"
	"fmt"
	"github.com/esonhugh/go-rex-java/constants"
	"io"
)

// NewArray represents a new array in Java serialization
type NewArray struct {
	*BaseElement
	ArrayDescription *ClassDesc
	Type             string
	Values           []interface{}
}

// NewNewArray creates a new NewArray instance
func NewNewArray(stream *Stream) *NewArray {
	return &NewArray{
		BaseElement:      NewBaseElement(stream),
		ArrayDescription: nil,
		Type:             "",
		Values:           make([]interface{}, 0),
	}
}

// Decode deserializes a NewArray from the given reader
func (na *NewArray) Decode(reader io.Reader, stream *Stream) error {
	na.Stream = stream

	// Decode array class description (ClassDesc)
    na.ArrayDescription = NewClassDescInstance(stream)
    if err := na.ArrayDescription.Decode(reader, stream); err != nil {
        // Be tolerant for empty/minimal input
        if err == io.EOF || err == io.ErrUnexpectedEOF {
            return nil
        }
        return &DecodeError{Message: "failed to decode array class description"}
    }

	// Add reference to stream
	if stream != nil {
		stream.AddReference(na)
	}

	// Extract type from class description
	typeStr, err := na.arrayType()
	if err != nil {
		return &DecodeError{Message: fmt.Sprintf("failed to determine array type: %v", err)}
	}
	na.Type = typeStr

	// Read array length (4 bytes, int32)
	lengthBytes := make([]byte, constants.SIZE_INT)
    if _, err := io.ReadFull(reader, lengthBytes); err != nil {
        if err == io.EOF || err == io.ErrUnexpectedEOF {
            return nil
        }
        return &DecodeError{Message: "failed to read array length"}
    }
	arrayLength := int32(binary.BigEndian.Uint32(lengthBytes))

	// Decode array values based on type
	na.Values = make([]interface{}, 0, arrayLength)
	for i := int32(0); i < arrayLength; i++ {
		value, err := na.decodeValue(reader)
		if err != nil {
			return fmt.Errorf("failed to decode array element %d: %w", i, err)
		}
		na.Values = append(na.Values, value)
	}

	return nil
}

// Encode serializes the NewArray to bytes
func (na *NewArray) Encode() ([]byte, error) {
	return na.EncodeWithContext(nil)
}

// EncodeWithContext serializes the NewArray with a shared encode context
func (na *NewArray) EncodeWithContext(ctx *EncodeContext) ([]byte, error) {
	if na.ArrayDescription == nil {
		return nil, &EncodeError{Message: "array description is nil"}
	}

	encoded := make([]byte, 0, 256)

	// Encode array description using ClassDesc.EncodeWithContext
	descBytes, err := na.ArrayDescription.EncodeWithContext(ctx)
	if err != nil {
		return nil, err
	}
	encoded = append(encoded, descBytes...)

	// Encode array length (4 bytes, int32)
	lengthBytes := make([]byte, constants.SIZE_INT)
	binary.BigEndian.PutUint32(lengthBytes, uint32(len(na.Values)))
	encoded = append(encoded, lengthBytes...)

	// Encode array values
	for _, value := range na.Values {
		valueBytes, err := na.encodeValueWithContext(value, ctx)
		if err != nil {
			return nil, err
		}
		encoded = append(encoded, valueBytes...)
	}

	return encoded, nil
}

// String returns a string representation of the NewArray
func (na *NewArray) String() string {
	return "NewArray"
}

// arrayType extracts the array element type from the class description
func (na *NewArray) arrayType() (string, error) {
	if na.ArrayDescription == nil {
		return "", fmt.Errorf("empty array description")
	}

	desc := na.ArrayDescription.Description
	if desc == nil {
		return "", fmt.Errorf("array description is nil")
	}

	// Handle Reference - resolve if needed
	var newClassDesc *NewClassDesc
	switch d := desc.(type) {
	case *NewClassDesc:
		newClassDesc = d
	case *Reference:
		ref := d.Handle - constants.BASE_WIRE_HANDLE
		if na.Stream != nil && ref < uint32(len(na.Stream.References)) {
			refElement := na.Stream.References[ref]
			if refDesc, ok := refElement.(*NewClassDesc); ok {
				newClassDesc = refDesc
			} else if refClassDesc, ok := refElement.(*ClassDesc); ok && refClassDesc.Description != nil {
				// Resolve nested ClassDesc
				if nestedDesc, ok := refClassDesc.Description.(*NewClassDesc); ok {
					newClassDesc = nestedDesc
				}
			}
		}
	case *NullReference:
		// For null reference, we can't determine the type, but continue with a default
		return "object", nil
	}

	if newClassDesc == nil {
		// If we can't get class description, try to continue with object type as fallback
		// This allows parsing to continue for complex payloads
		return "object", nil
	}

	if newClassDesc.ClassName == nil {
		return "", fmt.Errorf("class description has no class name")
	}

	className := newClassDesc.ClassName.String()

	// Array type should start with '['
	if len(className) == 0 || className[0] != '[' {
		return "", fmt.Errorf("unsupported array description: %s", className)
	}

    // Get the element type code (count leading '[' to detect nested arrays)
    typeStartIndex := 0
    for typeStartIndex < len(className) && className[typeStartIndex] == '[' {
        typeStartIndex++
    }

    // If there are more than one '[' then this array's element is itself an array.
    // Return the element array type string (preserving the leading '[' for the nested array)
    if typeStartIndex > 1 {
        return className[1:], nil
    }

	if typeStartIndex >= len(className) {
		return "", fmt.Errorf("invalid array type format: %s", className)
	}

	typeCode := className[typeStartIndex]

	// Check if it's a primitive type
	switch typeCode {
	case constants.TYPE_BYTE:
		return "byte", nil
	case constants.TYPE_CHAR:
		return "char", nil
	case constants.TYPE_DOUBLE:
		return "double", nil
	case constants.TYPE_FLOAT:
		return "float", nil
	case constants.TYPE_INT:
		return "int", nil
	case constants.TYPE_LONG:
		return "long", nil
	case constants.TYPE_SHORT:
		return "short", nil
	case constants.TYPE_BOOLEAN:
		return "boolean", nil
	case constants.TYPE_ARRAY: // '[' - nested array
		// For nested arrays, return the full type string
		return className, nil
	case constants.TYPE_OBJECT: // 'L'
		// Extract object class name (from 'L' to ';')
		objStart := typeStartIndex + 1
		if objStart < len(className) {
			if semicolonIndex := findChar(className, objStart, ';'); semicolonIndex > 0 {
				return className[objStart:semicolonIndex], nil
			}
		}
		return "", fmt.Errorf("invalid object array type format: %s", className)
	default:
		return "", fmt.Errorf("unsupported array type code: %c", typeCode)
	}
}

// findChar finds a character in a string starting from given index
func findChar(s string, start int, c byte) int {
	for i := start; i < len(s); i++ {
		if s[i] == c {
			return i
		}
	}
	return -1
}

// decodeValue decodes a single array element based on the array type
func (na *NewArray) decodeValue(reader io.Reader) (interface{}, error) {
	switch na.Type {
	case "byte":
		bytes := make([]byte, 1)
		if _, err := io.ReadFull(reader, bytes); err != nil {
			return nil, &DecodeError{Message: "failed to read byte value"}
		}
		return int8(bytes[0]), nil
	case "char":
		bytes := make([]byte, 2)
		if _, err := io.ReadFull(reader, bytes); err != nil {
			return nil, &DecodeError{Message: "failed to read char value"}
		}
		return int16(binary.BigEndian.Uint16(bytes)), nil
	case "double":
		bytes := make([]byte, 8)
		if _, err := io.ReadFull(reader, bytes); err != nil {
			return nil, &DecodeError{Message: "failed to read double value"}
		}
		return binary.BigEndian.Uint64(bytes), nil
	case "float":
		bytes := make([]byte, 4)
		if _, err := io.ReadFull(reader, bytes); err != nil {
			return nil, &DecodeError{Message: "failed to read float value"}
		}
		return binary.BigEndian.Uint32(bytes), nil
	case "int":
		bytes := make([]byte, 4)
		if _, err := io.ReadFull(reader, bytes); err != nil {
			return nil, &DecodeError{Message: "failed to read int value"}
		}
		return int32(binary.BigEndian.Uint32(bytes)), nil
	case "long":
		bytes := make([]byte, 8)
		if _, err := io.ReadFull(reader, bytes); err != nil {
			return nil, &DecodeError{Message: "failed to read long value"}
		}
		return int64(binary.BigEndian.Uint64(bytes)), nil
	case "short":
		bytes := make([]byte, 2)
		if _, err := io.ReadFull(reader, bytes); err != nil {
			return nil, &DecodeError{Message: "failed to read short value"}
		}
		return int16(binary.BigEndian.Uint16(bytes)), nil
	case "boolean":
		bytes := make([]byte, 1)
		if _, err := io.ReadFull(reader, bytes); err != nil {
			return nil, &DecodeError{Message: "failed to read boolean value"}
		}
		return bytes[0] != 0, nil
    default:
        // Object type or nested array - decode as element via DecodeElement so that
        // the element opcode (e.g., TC_ARRAY for nested arrays) is properly consumed.
        elem, err := DecodeElement(reader, na.Stream)
        if err != nil {
            // Be tolerant: if decode fails, return a null reference to allow parsing to continue
            if err == io.EOF || err == io.ErrUnexpectedEOF {
                return NewNullReference(na.Stream), nil
            }
            return nil, err
        }
	return elem, nil
	}
}

// encodeValue encodes a single array element (without context)
func (na *NewArray) encodeValue(value interface{}) ([]byte, error) {
	return na.encodeValueWithContext(value, nil)
}

// encodeValueWithContext encodes a single array element with context
func (na *NewArray) encodeValueWithContext(value interface{}, ctx *EncodeContext) ([]byte, error) {
	switch na.Type {
	case "byte":
		if val, ok := value.(int8); ok {
			return []byte{byte(val)}, nil
		}
	case "char":
		if val, ok := value.(int16); ok {
			bytes := make([]byte, 2)
			binary.BigEndian.PutUint16(bytes, uint16(val))
			return bytes, nil
		}
	case "double":
		if val, ok := value.(uint64); ok {
			bytes := make([]byte, 8)
			binary.BigEndian.PutUint64(bytes, val)
			return bytes, nil
		}
	case "float":
		if val, ok := value.(uint32); ok {
			bytes := make([]byte, 4)
			binary.BigEndian.PutUint32(bytes, val)
			return bytes, nil
		}
	case "int":
		if val, ok := value.(int32); ok {
			bytes := make([]byte, 4)
			binary.BigEndian.PutUint32(bytes, uint32(val))
			return bytes, nil
		}
	case "long":
		if val, ok := value.(int64); ok {
			bytes := make([]byte, 8)
			binary.BigEndian.PutUint64(bytes, uint64(val))
			return bytes, nil
		}
	case "short":
		if val, ok := value.(int16); ok {
			bytes := make([]byte, 2)
			binary.BigEndian.PutUint16(bytes, uint16(val))
			return bytes, nil
		}
	case "boolean":
		if val, ok := value.(bool); ok {
			if val {
				return []byte{1}, nil
			}
			return []byte{0}, nil
		}
	default:
		// Object type or nested array - encode as element with context
		if elem, ok := value.(Element); ok {
			if ctx != nil {
				return EncodeElementWithContext(elem, ctx)
			}
			return EncodeElementWithReferences(elem, na.Stream)
		}
	}

	return nil, &EncodeError{Message: "failed to encode array value"}
}

// marshalNewArray marshals a NewArray to JSON-friendly format
func marshalNewArray(na *NewArray) interface{} {
	if na == nil {
		return nil
	}
	return map[string]interface{}{
		"type":              "NewArray",
		"array_description": marshalClassDesc(na.ArrayDescription),
		"type_info":         na.Type,
		"values":            na.Values,
	}
}
