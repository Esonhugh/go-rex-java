package model

import (
	"bytes"
	"testing"
)

func TestNewField(t *testing.T) {
	field := NewField(nil)

	if field.Type != "" {
		t.Errorf("Expected empty type, got %q", field.Type)
	}

	if field.Name != nil {
		t.Error("Expected name to be nil")
	}

	if field.FieldType != nil {
		t.Error("Expected field type to be nil")
	}
}

func TestFieldIsPrimitive(t *testing.T) {
	field := &Field{Type: Int}

	if !field.IsPrimitive() {
		t.Error("Expected int to be primitive")
	}

	field.Type = "string"
	if field.IsPrimitive() {
		t.Error("Expected string to not be primitive")
	}

	field.Type = Byte
	if !field.IsPrimitive() {
		t.Error("Expected byte to be primitive")
	}
}

func TestFieldIsObject(t *testing.T) {
	field := &Field{Type: Array}

	if !field.IsObject() {
		t.Error("Expected array to be object")
	}

	field.Type = Object
	if !field.IsObject() {
		t.Error("Expected object to be object")
	}

	field.Type = Int
	if field.IsObject() {
		t.Error("Expected int to not be object")
	}
}

func TestFieldIsTypeValid(t *testing.T) {
	field := &Field{Type: Int}

	if !field.IsTypeValid() {
		t.Error("Expected int to be valid type")
	}

	field.Type = "invalid"
	if field.IsTypeValid() {
		t.Error("Expected invalid to not be valid type")
	}
}

func TestFieldString(t *testing.T) {
	field := &Field{
		Type: Int,
		Name: NewUtf(nil, "value"),
	}

	str := field.String()
	expected := "value (int)"
	if str != expected {
		t.Errorf("Expected %q, got %q", expected, str)
	}
}

func TestFieldStringWithFieldType(t *testing.T) {
	field := &Field{
		Type:      Object,
		Name:      NewUtf(nil, "obj"),
		FieldType: NewUtf(nil, "java.lang.String"),
	}

	str := field.String()
	expected := "obj (java.lang.String)"
	if str != expected {
		t.Errorf("Expected %q, got %q", expected, str)
	}
}

func TestFieldStringNilName(t *testing.T) {
	field := &Field{Type: Int}

	str := field.String()
	expected := "Field(nil)"
	if str != expected {
		t.Errorf("Expected %q, got %q", expected, str)
	}
}

func TestFieldDecode(t *testing.T) {
	// Create test data: type code + name (length + content)
	data := []byte{
		0x49,       // 'I' for int
		0x00, 0x05, // name length = 5
		'h', 'e', 'l', 'l', 'o', // "hello"
	}

	reader := bytes.NewReader(data)
	field := NewField(nil)

	err := field.Decode(reader, nil)
	if err != nil {
		t.Fatalf("Failed to decode field: %v", err)
	}

	if field.Type != Int {
		t.Errorf("Expected type 'int', got %q", field.Type)
	}

	if field.Name == nil {
		t.Fatal("Expected name to be set")
	}

	if field.Name.Contents != "hello" {
		t.Errorf("Expected name 'hello', got %q", field.Name.Contents)
	}
}

func TestFieldDecodeObject(t *testing.T) {
	// Create test data: type code + name + TC_STRING + field type
	data := []byte{
		0x4C,       // 'L' for object
		0x00, 0x05, // name length = 5
		'h', 'e', 'l', 'l', 'o', // "hello"
		0x74,       // TC_STRING
		0x00, 0x10, // field type length = 16
		'j', 'a', 'v', 'a', '.', 'l', 'a', 'n', 'g', '.', 'S', 't', 'r', 'i', 'n', 'g', // "java.lang.String"
	}

	reader := bytes.NewReader(data)
	field := NewField(nil)

	err := field.Decode(reader, nil)
	if err != nil {
		t.Fatalf("Failed to decode object field: %v", err)
	}

	if field.Type != Object {
		t.Errorf("Expected type 'object', got %q", field.Type)
	}

	if field.Name == nil {
		t.Fatal("Expected name to be set")
	}

	if field.Name.Contents != "hello" {
		t.Errorf("Expected name 'hello', got %q", field.Name.Contents)
	}

	if field.FieldType == nil {
		t.Fatal("Expected field type to be set")
	}

	if field.FieldType.Contents != "java.lang.String" {
		t.Errorf("Expected field type 'java.lang.String', got %q", field.FieldType.Contents)
	}
}

func TestFieldEncode(t *testing.T) {
	field := &Field{
		Type: Int,
		Name: NewUtf(nil, "value"),
	}

	encoded, err := field.Encode()
	if err != nil {
		t.Fatalf("Failed to encode field: %v", err)
	}

	// Check type code
	if encoded[0] != 0x49 { // 'I'
		t.Errorf("Expected type code 0x49, got 0x%x", encoded[0])
	}

	// Check name length
	expectedNameLength := []byte{0x00, 0x05} // 5
	if !bytes.Equal(encoded[1:3], expectedNameLength) {
		t.Errorf("Expected name length %v, got %v", expectedNameLength, encoded[1:3])
	}

	// Check name content
	expectedName := []byte("value")
	if !bytes.Equal(encoded[3:8], expectedName) {
		t.Errorf("Expected name %v, got %v", expectedName, encoded[3:8])
	}
}
