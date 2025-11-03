package model

import (
	"bytes"
	"github.com/esonhugh/go-rex-java/constants"
	"testing"
)

func TestDecodeElement(t *testing.T) {
	tests := []struct {
		name     string
		opcode   byte
		expected string
		hasError bool
	}{
		{"TC_NULL", constants.TC_NULL, "NullReference", false},
		{"TC_REFERENCE", constants.TC_REFERENCE, "Reference", true},    // Needs 4 bytes for handle
		{"TC_CLASSDESC", constants.TC_CLASSDESC, "NewClassDesc", true}, // Needs more data
		{"TC_OBJECT", constants.TC_OBJECT, "NewObject", true},          // Needs class description
		{"TC_STRING", constants.TC_STRING, "Utf", true},                // Needs length + content
		{"TC_ARRAY", constants.TC_ARRAY, "NewArray", false},            // Currently returns success
		{"TC_CLASS", constants.TC_CLASS, "NewClass", true},            // Needs class description
		{"TC_BLOCKDATA", constants.TC_BLOCKDATA, "BlockData", true},    // Needs length + data
		{"TC_ENDBLOCKDATA", constants.TC_ENDBLOCKDATA, "EndBlockData", false},
		{"TC_RESET", constants.TC_RESET, "Reset", false},
		{"TC_BLOCKDATALONG", constants.TC_BLOCKDATALONG, "BlockDataLong", false},
		{"TC_LONGSTRING", constants.TC_LONGSTRING, "LongUtf", false},                // Currently returns success
		{"TC_PROXYCLASSDESC", constants.TC_PROXYCLASSDESC, "ProxyClassDesc", false}, // Currently returns success
		{"TC_ENUM", constants.TC_ENUM, "NewEnum", false},                            // Currently returns success
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := []byte{tt.opcode}
			reader := bytes.NewReader(data)

			element, err := DecodeElement(reader, nil)
			if tt.hasError {
				if err == nil {
					t.Errorf("Expected error for %s, got nil", tt.name)
				}
				return
			}

			if err != nil {
				t.Fatalf("Failed to decode element: %v", err)
			}

			if element == nil {
				t.Fatal("Expected element to be non-nil")
			}

			// Check that the element is of the expected type
			elementType := element.String()
			if elementType != tt.expected {
				t.Errorf("Expected element type %q, got %q", tt.expected, elementType)
			}
		})
	}
}

func TestDecodeElementInvalidOpcode(t *testing.T) {
	data := []byte{0xFF} // Invalid opcode
	reader := bytes.NewReader(data)

	_, err := DecodeElement(reader, nil)
	if err == nil {
		t.Error("Expected error for invalid opcode")
	}
}

func TestDecodeElementTCException(t *testing.T) {
	data := []byte{0x7B} // TC_EXCEPTION
	reader := bytes.NewReader(data)

	_, err := DecodeElement(reader, nil)
	if err == nil {
		t.Error("Expected error for TC_EXCEPTION")
	}
}

func TestEncodeElement(t *testing.T) {
	tests := []struct {
		name     string
		element  Element
		expected byte
		hasError bool
	}{
		{"NullReference", NewNullReference(nil), constants.TC_NULL, false},
		{"Reference", NewReference(nil, 0), constants.TC_REFERENCE, false},
		{"NewClassDesc", NewNewClassDesc(nil), constants.TC_CLASSDESC, false},
		{"NewObject", NewNewObject(nil), constants.TC_OBJECT, true}, // Needs class description
		{"Utf", NewUtf(nil, "test"), constants.TC_STRING, false},
		{"NewArray", func() Element {
			arr := NewNewArray(nil)
			arr.ArrayDescription = NewClassDescInstance(nil)
			arr.ArrayDescription.Description = NewNullReference(nil)
			return arr
		}(), constants.TC_ARRAY, false},
		{"NewClass", func() Element {
			nc := NewNewClass(nil)
			nc.ClassDescription = NewClassDescInstance(nil)
			nc.ClassDescription.Description = NewNullReference(nil)
			return nc
		}(), constants.TC_CLASS, false},
		{"BlockData", NewBlockData(nil), constants.TC_BLOCKDATA, false},
		{"EndBlockData", NewEndBlockData(nil), constants.TC_ENDBLOCKDATA, false},
		{"Reset", NewReset(nil), constants.TC_RESET, false},
		{"BlockDataLong", NewBlockDataLong(nil), constants.TC_BLOCKDATALONG, false},
		{"LongUtf", NewLongUtf(nil), constants.TC_LONGSTRING, false},
		{"ProxyClassDesc", func() Element {
			pcd := NewProxyClassDesc(nil)
			pcd.ClassAnnotation = NewAnnotation(nil)
			pcd.SuperClass = NewClassDescInstance(nil)
			pcd.SuperClass.Description = NewNullReference(nil)
			return pcd
		}(), constants.TC_PROXYCLASSDESC, false},
		{"NewEnum", NewNewEnum(nil), constants.TC_ENUM, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encoded, err := EncodeElement(tt.element)
			if tt.hasError {
				if err == nil {
					t.Errorf("Expected error for %s, got nil", tt.name)
				}
				return
			}

			if err != nil {
				t.Fatalf("Failed to encode element: %v", err)
			}

			if len(encoded) == 0 {
				t.Fatal("Expected encoded data to be non-empty")
			}

			if encoded[0] != tt.expected {
				t.Errorf("Expected opcode 0x%02x, got 0x%02x", tt.expected, encoded[0])
			}
		})
	}
}

func TestEncodeElementInvalidType(t *testing.T) {
	// Create a custom element that's not handled
	customElement := &BaseElement{}

	_, err := EncodeElement(customElement)
	if err == nil {
		t.Error("Expected error for unsupported element type")
	}
}

func TestBaseElement(t *testing.T) {
	element := NewBaseElement(nil)

	if element.Stream != nil {
		t.Error("Expected stream to be nil")
	}

	// Test default implementations
	err := element.Decode(nil, nil)
	if err != nil {
		t.Errorf("Expected no error from default Decode, got %v", err)
	}

	encoded, err := element.Encode()
	if err != nil {
		t.Errorf("Expected no error from default Encode, got %v", err)
	}

	if len(encoded) != 0 {
		t.Errorf("Expected empty encoded data, got %v", encoded)
	}

	str := element.String()
	if str != "Element" {
		t.Errorf("Expected 'Element', got %q", str)
	}
}
