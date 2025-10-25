// Package constants provides Java serialization constants
package constants

// Java serialization stream constants
const (
	// Stream magic number (0xaced)
	StreamMagic = 0xaced
	// Stream version (5)
	StreamVersion = 5
)

// Type codes for Java serialization
const (
	TC_NULL           = 0x70
	TC_REFERENCE      = 0x71
	TC_CLASSDESC      = 0x72
	TC_OBJECT         = 0x73
	TC_STRING         = 0x74
	TC_ARRAY          = 0x75
	TC_CLASS          = 0x76
	TC_BLOCKDATA      = 0x77
	TC_ENDBLOCKDATA   = 0x78
	TC_RESET          = 0x79
	TC_BLOCKDATALONG  = 0x7A
	TC_EXCEPTION      = 0x7B
	TC_LONGSTRING     = 0x7C
	TC_PROXYCLASSDESC = 0x7D
	TC_ENUM           = 0x7E
)

// Base wire handle for references
const BASE_WIRE_HANDLE = 0x7E0000

// Size constants for different data types
const (
	SIZE_BYTE   = 1
	SIZE_SHORT  = 2
	SIZE_INT    = 4
	SIZE_LONG   = 8
	SIZE_DOUBLE = 8
	SIZE_FLOAT  = 4
)

// Serialization flags
const (
	SC_WRITE_METHOD   = 0x01 // if SC_SERIALIZABLE
	SC_BLOCK_DATA     = 0x08 // if SC_EXTERNALIZABLE
	SC_SERIALIZABLE   = 0x02
	SC_EXTERNALIZABLE = 0x04
	SC_ENUM           = 0x10
)

// Primitive type code constants
const (
	TYPE_BYTE    = 'B'
	TYPE_CHAR    = 'C'
	TYPE_DOUBLE  = 'D'
	TYPE_FLOAT   = 'F'
	TYPE_INT     = 'I'
	TYPE_LONG    = 'J'
	TYPE_SHORT   = 'S'
	TYPE_BOOLEAN = 'Z'
	TYPE_ARRAY   = '['
	TYPE_OBJECT  = 'L'
)

// Primitive type codes mapping
var PrimitiveTypeCodes = map[byte]string{
	TYPE_BYTE:    "byte",
	TYPE_CHAR:    "char",
	TYPE_DOUBLE:  "double",
	TYPE_FLOAT:   "float",
	TYPE_INT:     "int",
	TYPE_LONG:    "long",
	TYPE_SHORT:   "short",
	TYPE_BOOLEAN: "boolean",
}

// Object type codes mapping
var ObjectTypeCodes = map[byte]string{
	TYPE_ARRAY:  "array",
	TYPE_OBJECT: "object",
}

// Combined type codes
var TypeCodes = map[byte]string{
	TYPE_BYTE:    "byte",
	TYPE_CHAR:    "char",
	TYPE_DOUBLE:  "double",
	TYPE_FLOAT:   "float",
	TYPE_INT:     "int",
	TYPE_LONG:    "long",
	TYPE_SHORT:   "short",
	TYPE_BOOLEAN: "boolean",
	TYPE_ARRAY:   "array",
	TYPE_OBJECT:  "object",
}
