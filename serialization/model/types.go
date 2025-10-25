package model

import "fmt"

// ObjectType represents the type of a Java object
type ObjectType string

const (
	Byte    ObjectType = "byte"
	Char    ObjectType = "char"
	Double  ObjectType = "double"
	Float   ObjectType = "float"
	Int     ObjectType = "int"
	Long    ObjectType = "long"
	Short   ObjectType = "short"
	Boolean ObjectType = "boolean"
	Array   ObjectType = "array"
	Object  ObjectType = "object"
)

// SerializationFlag represents serialization flags
type SerializationFlag uint8

const (
	SC_WRITE_METHOD   SerializationFlag = 0x01 // if SC_SERIALIZABLE
	SC_BLOCK_DATA     SerializationFlag = 0x08 // if SC_EXTERNALIZABLE
	SC_SERIALIZABLE   SerializationFlag = 0x02
	SC_EXTERNALIZABLE SerializationFlag = 0x04
	SC_ENUM           SerializationFlag = 0x10
)

// TypeCode represents a type code in Java serialization
type TypeCode byte

const (
	TC_NULL           TypeCode = 0x70
	TC_REFERENCE      TypeCode = 0x71
	TC_CLASSDESC      TypeCode = 0x72
	TC_OBJECT         TypeCode = 0x73
	TC_STRING         TypeCode = 0x74
	TC_ARRAY          TypeCode = 0x75
	TC_CLASS          TypeCode = 0x76
	TC_BLOCKDATA      TypeCode = 0x77
	TC_ENDBLOCKDATA   TypeCode = 0x78
	TC_RESET          TypeCode = 0x79
	TC_BLOCKDATALONG  TypeCode = 0x7A
	TC_EXCEPTION      TypeCode = 0x7B
	TC_LONGSTRING     TypeCode = 0x7C
	TC_PROXYCLASSDESC TypeCode = 0x7D
	TC_ENUM           TypeCode = 0x7E
)

// PrimitiveValue represents a primitive value with its type
type PrimitiveValue struct {
	Type  ObjectType
	Value interface{}
}

// NewPrimitiveValue creates a new PrimitiveValue
func NewPrimitiveValue(objType ObjectType, value interface{}) *PrimitiveValue {
	return &PrimitiveValue{
		Type:  objType,
		Value: value,
	}
}

// String returns a string representation of the PrimitiveValue
func (pv *PrimitiveValue) String() string {
	if pv == nil {
		return "nil"
	}

	switch pv.Type {
	case Object:
		if element, ok := pv.Value.(Element); ok {
			return element.String()
		}
		return "Object"
	default:
		return pv.Type.String() + "(" + formatValue(pv.Value) + ")"
	}
}

// formatValue formats a value for display
func formatValue(value interface{}) string {
	if value == nil {
		return "nil"
	}

	switch v := value.(type) {
	case bool:
		if v {
			return "true"
		}
		return "false"
	case int8, int16, int32, int64, uint8, uint16, uint32, uint64, float32, float64:
		return fmt.Sprintf("%v", v)
	case string:
		return v
	default:
		return "unknown"
	}
}

// IsPrimitive checks if the object type is primitive
func (ot ObjectType) IsPrimitive() bool {
	switch ot {
	case Byte, Char, Double, Float, Int, Long, Short, Boolean:
		return true
	default:
		return false
	}
}

// IsObject checks if the object type is an object
func (ot ObjectType) IsObject() bool {
	switch ot {
	case Array, Object:
		return true
	default:
		return false
	}
}

// String returns the string representation of the object type
func (ot ObjectType) String() string {
	return string(ot)
}

// String returns the string representation of the serialization flag
func (sf SerializationFlag) String() string {
	switch sf {
	case SC_WRITE_METHOD:
		return "SC_WRITE_METHOD"
	case SC_BLOCK_DATA:
		return "SC_BLOCK_DATA"
	case SC_SERIALIZABLE:
		return "SC_SERIALIZABLE"
	case SC_EXTERNALIZABLE:
		return "SC_EXTERNALIZABLE"
	case SC_ENUM:
		return "SC_ENUM"
	default:
		return "UNKNOWN"
	}
}

// String returns the string representation of the type code
func (tc TypeCode) String() string {
	switch tc {
	case TC_NULL:
		return "TC_NULL"
	case TC_REFERENCE:
		return "TC_REFERENCE"
	case TC_CLASSDESC:
		return "TC_CLASSDESC"
	case TC_OBJECT:
		return "TC_OBJECT"
	case TC_STRING:
		return "TC_STRING"
	case TC_ARRAY:
		return "TC_ARRAY"
	case TC_CLASS:
		return "TC_CLASS"
	case TC_BLOCKDATA:
		return "TC_BLOCKDATA"
	case TC_ENDBLOCKDATA:
		return "TC_ENDBLOCKDATA"
	case TC_RESET:
		return "TC_RESET"
	case TC_BLOCKDATALONG:
		return "TC_BLOCKDATALONG"
	case TC_EXCEPTION:
		return "TC_EXCEPTION"
	case TC_LONGSTRING:
		return "TC_LONGSTRING"
	case TC_PROXYCLASSDESC:
		return "TC_PROXYCLASSDESC"
	case TC_ENUM:
		return "TC_ENUM"
	default:
		return "UNKNOWN"
	}
}
