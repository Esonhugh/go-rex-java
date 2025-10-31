package model

import (
	"encoding/json"
	"testing"
)

// TestStreamMarshalJSON tests JSON marshaling of Stream
func TestStreamMarshalJSON(t *testing.T) {
	stream := NewStream()
	stream.Magic = 0xaced
	stream.Version = 5

	// Add a test UTF element
	utf := NewUtf(stream, "Hello World")
	stream.Contents = append(stream.Contents, utf)
	stream.AddReference(utf)

	jsonData, err := json.Marshal(stream)
	if err != nil {
		t.Fatalf("Failed to marshal Stream to JSON: %v", err)
	}

	// Verify JSON output is not empty
	if len(jsonData) == 0 {
		t.Fatal("JSON output is empty")
	}

	// Verify JSON output contains expected fields
	var result map[string]interface{}
	if err := json.Unmarshal(jsonData, &result); err != nil {
		t.Fatalf("Failed to unmarshal JSON: %v", err)
	}

	if result["type"] != "Stream" {
		t.Errorf("Expected type 'Stream', got '%v'", result["type"])
	}

	if result["magic"] != "0xaced" {
		t.Errorf("Expected magic '0xaced', got '%v'", result["magic"])
	}

	if result["version"] != float64(5) {
		t.Errorf("Expected version 5, got %v", result["version"])
	}
}

// TestUtfMarshalJSON tests JSON marshaling of Utf
func TestUtfMarshalJSON(t *testing.T) {
	stream := NewStream()
	utf := NewUtf(stream, "test string")

	jsonData, err := json.Marshal(utf)
	if err != nil {
		t.Fatalf("Failed to marshal Utf to JSON: %v", err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(jsonData, &result); err != nil {
		t.Fatalf("Failed to unmarshal JSON: %v", err)
	}

	if result["type"] != "Utf" {
		t.Errorf("Expected type 'Utf', got '%v'", result["type"])
	}

	if result["contents"] != "test string" {
		t.Errorf("Expected contents 'test string', got '%v'", result["contents"])
	}
}

// TestBlockDataMarshalJSON tests JSON marshaling of BlockData
func TestBlockDataMarshalJSON(t *testing.T) {
	stream := NewStream()
	bd := NewBlockData(stream)
	bd.Data = []byte{0x12, 0x34, 0x56, 0x78}

	jsonData, err := json.Marshal(bd)
	if err != nil {
		t.Fatalf("Failed to marshal BlockData to JSON: %v", err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(jsonData, &result); err != nil {
		t.Fatalf("Failed to unmarshal JSON: %v", err)
	}

	if result["type"] != "BlockData" {
		t.Errorf("Expected type 'BlockData', got '%v'", result["type"])
	}

	data, ok := result["data"].([]interface{})
	if !ok {
		t.Fatalf("Expected data to be a slice, got %T", result["data"])
	}

	if len(data) != 4 {
		t.Errorf("Expected data length 4, got %d", len(data))
	}
}

// TestReferenceMarshalJSON tests JSON marshaling of Reference
func TestReferenceMarshalJSON(t *testing.T) {
	stream := NewStream()
	ref := NewReference(stream, 0x00001234)

	jsonData, err := json.Marshal(ref)
	if err != nil {
		t.Fatalf("Failed to marshal Reference to JSON: %v", err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(jsonData, &result); err != nil {
		t.Fatalf("Failed to unmarshal JSON: %v", err)
	}

	if result["type"] != "Reference" {
		t.Errorf("Expected type 'Reference', got '%v'", result["type"])
	}

	if result["handle"] != "0x1234" {
		t.Errorf("Expected handle '0x1234', got '%v'", result["handle"])
	}
}

// TestNullReferenceMarshalJSON tests JSON marshaling of NullReference
func TestNullReferenceMarshalJSON(t *testing.T) {
	stream := NewStream()
	nr := NewNullReference(stream)

	jsonData, err := json.Marshal(nr)
	if err != nil {
		t.Fatalf("Failed to marshal NullReference to JSON: %v", err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(jsonData, &result); err != nil {
		t.Fatalf("Failed to unmarshal JSON: %v", err)
	}

	if result["type"] != "NullReference" {
		t.Errorf("Expected type 'NullReference', got '%v'", result["type"])
	}
}

// TestNewObjectMarshalJSON tests JSON marshaling of NewObject
func TestNewObjectMarshalJSON(t *testing.T) {
	stream := NewStream()
	no := NewNewObject(stream)

	// Create a simple class description
	classDesc := NewNewClassDesc(stream)
	classDesc.ClassName = NewUtf(stream, "TestClass")
	classDesc.SerialVersion = 1234567890123456789
	classDesc.Flags = 0x02

	no.ClassDesc = &ClassDesc{
		BaseElement: NewBaseElement(stream),
		Description: classDesc,
	}

	// Add some class data
	pv1 := NewPrimitiveValue(Int, int32(42))
	pv2 := NewPrimitiveValue(Boolean, true)
	no.ClassData = []*PrimitiveValue{pv1, pv2}

	jsonData, err := json.Marshal(no)
	if err != nil {
		t.Fatalf("Failed to marshal NewObject to JSON: %v", err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(jsonData, &result); err != nil {
		t.Fatalf("Failed to unmarshal JSON: %v", err)
	}

	if result["type"] != "NewObject" {
		t.Errorf("Expected type 'NewObject', got '%v'", result["type"])
	}
}

// TestNewClassDescMarshalJSON tests JSON marshaling of NewClassDesc
func TestNewClassDescMarshalJSON(t *testing.T) {
	stream := NewStream()
	ncd := NewNewClassDesc(stream)
	ncd.ClassName = NewUtf(stream, "TestClass")
	ncd.SerialVersion = 9876543210987654321
	ncd.Flags = 0x02

	// Add a field
	field := NewField(stream)
	field.Type = Int
	field.Name = NewUtf(stream, "testField")
	ncd.Fields = append(ncd.Fields, field)

	jsonData, err := json.Marshal(ncd)
	if err != nil {
		t.Fatalf("Failed to marshal NewClassDesc to JSON: %v", err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(jsonData, &result); err != nil {
		t.Fatalf("Failed to unmarshal JSON: %v", err)
	}

	if result["type"] != "NewClassDesc" {
		t.Errorf("Expected type 'NewClassDesc', got '%v'", result["type"])
	}

	fields, ok := result["fields"].([]interface{})
	if !ok {
		t.Fatalf("Expected fields to be a slice, got %T", result["fields"])
	}

	if len(fields) != 1 {
		t.Errorf("Expected 1 field, got %d", len(fields))
	}
}

// TestFieldMarshalJSON tests JSON marshaling of Field
func TestFieldMarshalJSON(t *testing.T) {
	stream := NewStream()
	field := NewField(stream)
	field.Type = Object
	field.Name = NewUtf(stream, "myField")

	jsonData, err := json.Marshal(field)
	if err != nil {
		t.Fatalf("Failed to marshal Field to JSON: %v", err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(jsonData, &result); err != nil {
		t.Fatalf("Failed to unmarshal JSON: %v", err)
	}

	if result["type"] != "object" {
		t.Errorf("Expected type 'object', got '%v'", result["type"])
	}

	if result["name"] != "myField" {
		t.Errorf("Expected name 'myField', got '%v'", result["name"])
	}
}

