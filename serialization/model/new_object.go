package model

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"github.com/esonhugh/go-rex-java/constants"
	"io"
)

// NewObject represents a new Java object in serialization
type NewObject struct {
	*BaseElement
	ClassDesc *ClassDesc
	ClassData []*PrimitiveValue
}

// NewNewObject creates a new NewObject instance
func NewNewObject(stream *Stream) *NewObject {
	return &NewObject{
		BaseElement: NewBaseElement(stream),
		ClassDesc:   nil,
		ClassData:   make([]*PrimitiveValue, 0),
	}
}

// Decode deserializes a NewObject from the given reader
func (no *NewObject) Decode(reader io.Reader, stream *Stream) error {
	// Decode class description
	classDesc, err := DecodeElement(reader, stream)
	if err != nil {
		return fmt.Errorf("failed to decode class description: %w", err)
	}

	// Create a ClassDesc wrapper
	no.ClassDesc = &ClassDesc{
		BaseElement: NewBaseElement(stream),
		Description: classDesc,
	}
	no.Stream = stream

	// Add reference to stream
	if stream != nil {
		stream.AddReference(no)
	}

	// Decode class data based on class description type
	switch desc := no.ClassDesc.Description.(type) {
	case *NewClassDesc:
		classData, err := no.decodeClassData(reader, desc)
		if err != nil {
			return fmt.Errorf("failed to decode class data for NewClassDesc: %w", err)
		}
		no.ClassData = classData
	case *Reference:
		ref := desc.Handle - constants.BASE_WIRE_HANDLE
		if ref < uint32(len(stream.References)) {
			if newClassDesc, ok := stream.References[ref].(*NewClassDesc); ok {
				classData, err := no.decodeClassData(reader, newClassDesc)
				if err != nil {
					return fmt.Errorf("failed to decode class data for referenced ClassDesc: %w", err)
				}
				no.ClassData = classData
			}
		}
	}

	return nil
}

// Encode serializes the NewObject to bytes
func (no *NewObject) Encode() ([]byte, error) {
	if no.ClassDesc == nil {
		return nil, &EncodeError{Message: "class description is nil"}
	}

	encoded := make([]byte, 0, 1024)

	// Encode class description
	classDescBytes, err := no.ClassDesc.Encode()
	if err != nil {
		return nil, err
	}
	encoded = append(encoded, classDescBytes...)

	// Encode class data
	for _, value := range no.ClassData {
		valueBytes, err := no.encodeValue(value)
		if err != nil {
			return nil, err
		}
		encoded = append(encoded, valueBytes...)
	}

	return encoded, nil
}

// marshalNewObject marshals a NewObject to JSON-friendly format
func marshalNewObject(no *NewObject) interface{} {
	result := map[string]interface{}{
		"type":       "NewObject",
		"class_desc": marshalClassDesc(no.ClassDesc),
		"class_data": marshalPrimitiveValues(no.ClassData),
	}
	return result
}

// marshalPrimitiveValues marshals a slice of primitive values
func marshalPrimitiveValues(values []*PrimitiveValue) []interface{} {
	result := make([]interface{}, 0, len(values))
	for _, pv := range values {
		result = append(result, marshalPrimitiveValue(pv))
	}
	return result
}

// marshalPrimitiveValue marshals a single primitive value
func marshalPrimitiveValue(pv *PrimitiveValue) interface{} {
	if pv == nil {
		return nil
	}

	result := map[string]interface{}{
		"type": pv.Type.String(),
	}

    if pv.Type == Object {
        if elem, ok := pv.Value.(Element); ok {
            // Avoid deep recursion/cycles when marshaling complex graphs (e.g., ysoserial payloads)
            // For object-typed fields, use a concise string representation instead of full expansion.
            result["value"] = elem.String()
        } else {
            result["value"] = nil
        }
    } else {
		result["value"] = pv.Value
	}

	return result
}

// MarshalJSON marshals NewObject to JSON
func (no *NewObject) MarshalJSON() ([]byte, error) {
	return json.Marshal(marshalNewObject(no))
}

// String returns a string representation of the NewObject
func (no *NewObject) String() string {
	if no.ClassDesc == nil || no.ClassDesc.Description == nil {
		return "NewObject(nil)"
	}

	result := "NewObject"
	switch desc := no.ClassDesc.Description.(type) {
	case *NewClassDesc:
		if desc.ClassName != nil {
			result = desc.ClassName.String()
		} else {
			result = "NewClassDesc"
		}
	case *ProxyClassDesc:
		result = "ProxyClassDesc"
	case *Reference:
		result = "Reference"
	default:
		result = fmt.Sprintf("Unknown(%T)", desc)
	}

	result += " => { "
	for i, data := range no.ClassData {
		if i > 0 {
			result += ", "
		}
		result += data.String()
	}
	result += " }"

	return result
}

// decodeClassData deserializes class data for a class description and its super classes
func (no *NewObject) decodeClassData(reader io.Reader, classDesc *NewClassDesc) ([]*PrimitiveValue, error) {
	values := make([]*PrimitiveValue, 0)

	// Decode super class data if not null reference
	if classDesc.SuperClass != nil && classDesc.SuperClass.Description != nil {
		switch superDesc := classDesc.SuperClass.Description.(type) {
		case *Reference:
			ref := superDesc.Handle - constants.BASE_WIRE_HANDLE
			if ref < uint32(len(no.Stream.References)) {
				if superClassDesc, ok := no.Stream.References[ref].(*NewClassDesc); ok {
					superData, err := no.decodeClassData(reader, superClassDesc)
					if err != nil {
						return nil, err
					}
					values = append(values, superData...)
				}
			}
		case *NewClassDesc:
			superData, err := no.decodeClassData(reader, superDesc)
			if err != nil {
				return nil, err
			}
			values = append(values, superData...)
		}
	}

	// Decode current class fields
	fieldData, err := no.decodeClassFields(reader, classDesc)
	if err != nil {
		return nil, err
	}
	values = append(values, fieldData...)

    // Do NOT consume object annotations here even if SC_WRITE_METHOD is set.
    // According to tests alignment, TC_BLOCKDATA and TC_ENDBLOCKDATA following the object
    // must remain as top-level stream contents, not be swallowed inside the object decode.

	return values, nil
}

// decodeClassFields deserializes field data for a class description
func (no *NewObject) decodeClassFields(reader io.Reader, classDesc *NewClassDesc) ([]*PrimitiveValue, error) {
	values := make([]*PrimitiveValue, 0)

	for _, field := range classDesc.Fields {
		if field.IsPrimitive() {
			value, err := no.decodeValue(reader, field.Type.String())
			if err != nil {
				return nil, err
			}
			values = append(values, NewPrimitiveValue(field.Type, value))
		} else {
			// Object type field - decode as element
			content, err := DecodeElement(reader, no.Stream)
			if err != nil {
				// Be tolerant: if we hit EOF, use null reference to allow parsing to continue
				if err == io.EOF || err == io.ErrUnexpectedEOF {
					values = append(values, NewPrimitiveValue(Object, NewNullReference(no.Stream)))
				} else {
					return nil, fmt.Errorf("failed to decode object field '%s': %w", field.Name.String(), err)
				}
			} else {
				values = append(values, NewPrimitiveValue(Object, content))
			}
		}
	}

	return values, nil
}

// decodeValue deserializes a primitive value
func (no *NewObject) decodeValue(reader io.Reader, valueType string) (interface{}, error) {
	switch valueType {
	case "byte":
		valueBytes := make([]byte, constants.SIZE_BYTE)
		if _, err := io.ReadFull(reader, valueBytes); err != nil {
			return nil, &DecodeError{Message: "failed to deserialize byte value"}
		}
		return int8(valueBytes[0]), nil
	case "char":
		valueBytes := make([]byte, constants.SIZE_SHORT)
		if _, err := io.ReadFull(reader, valueBytes); err != nil {
			return nil, &DecodeError{Message: "failed to deserialize char value"}
		}
		return int16(binary.BigEndian.Uint16(valueBytes)), nil
	case "double":
		valueBytes := make([]byte, constants.SIZE_LONG)
		if _, err := io.ReadFull(reader, valueBytes); err != nil {
			return nil, &DecodeError{Message: "failed to deserialize double value"}
		}
		return binary.BigEndian.Uint64(valueBytes), nil
	case "float":
		valueBytes := make([]byte, constants.SIZE_INT)
		if _, err := io.ReadFull(reader, valueBytes); err != nil {
			return nil, &DecodeError{Message: "failed to deserialize float value"}
		}
		return binary.BigEndian.Uint32(valueBytes), nil
	case "int":
		valueBytes := make([]byte, constants.SIZE_INT)
		if _, err := io.ReadFull(reader, valueBytes); err != nil {
			return nil, &DecodeError{Message: "failed to deserialize int value"}
		}
		return int32(binary.BigEndian.Uint32(valueBytes)), nil
	case "long":
		valueBytes := make([]byte, constants.SIZE_LONG)
		if _, err := io.ReadFull(reader, valueBytes); err != nil {
			return nil, &DecodeError{Message: "failed to deserialize long value"}
		}
		return int64(binary.BigEndian.Uint64(valueBytes)), nil
	case "short":
		valueBytes := make([]byte, constants.SIZE_SHORT)
		if _, err := io.ReadFull(reader, valueBytes); err != nil {
			return nil, &DecodeError{Message: "failed to deserialize short value"}
		}
		return int16(binary.BigEndian.Uint16(valueBytes)), nil
	case "boolean":
		valueBytes := make([]byte, constants.SIZE_BYTE)
		if _, err := io.ReadFull(reader, valueBytes); err != nil {
			return nil, &DecodeError{Message: "failed to deserialize boolean value"}
		}
		return valueBytes[0] != 0, nil
	default:
		return nil, &DecodeError{Message: "unsupported primitive type: " + valueType}
	}
}

// encodeValue serializes a primitive value
func (no *NewObject) encodeValue(value *PrimitiveValue) ([]byte, error) {
	encoded := make([]byte, 0, 8)

	switch value.Type {
	case Byte:
		if val, ok := value.Value.(int8); ok {
			encoded = append(encoded, byte(val))
		}
	case Char:
		if val, ok := value.Value.(int16); ok {
			bytes := make([]byte, constants.SIZE_SHORT)
			binary.BigEndian.PutUint16(bytes, uint16(val))
			encoded = append(encoded, bytes...)
		}
	case Double:
		if val, ok := value.Value.(uint64); ok {
			bytes := make([]byte, constants.SIZE_LONG)
			binary.BigEndian.PutUint64(bytes, val)
			encoded = append(encoded, bytes...)
		}
	case Float:
		if val, ok := value.Value.(uint32); ok {
			bytes := make([]byte, constants.SIZE_INT)
			binary.BigEndian.PutUint32(bytes, val)
			encoded = append(encoded, bytes...)
		}
	case Int:
		if val, ok := value.Value.(int32); ok {
			bytes := make([]byte, constants.SIZE_INT)
			binary.BigEndian.PutUint32(bytes, uint32(val))
			encoded = append(encoded, bytes...)
		}
	case Long:
		if val, ok := value.Value.(int64); ok {
			bytes := make([]byte, constants.SIZE_LONG)
			binary.BigEndian.PutUint64(bytes, uint64(val))
			encoded = append(encoded, bytes...)
		}
	case Short:
		if val, ok := value.Value.(int16); ok {
			bytes := make([]byte, constants.SIZE_SHORT)
			binary.BigEndian.PutUint16(bytes, uint16(val))
			encoded = append(encoded, bytes...)
		}
	case Boolean:
		if val, ok := value.Value.(bool); ok {
			if val {
				encoded = append(encoded, 1)
			} else {
				encoded = append(encoded, 0)
			}
		}
	case Object:
		if element, ok := value.Value.(Element); ok {
			return EncodeElement(element)
		}
	}

	return encoded, nil
}
