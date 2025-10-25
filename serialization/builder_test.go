package serialization

import (
	"github.com/esonhugh/go-rex-java/serialization/model"
	"testing"
)

func TestNewBuilder(t *testing.T) {
	builder := NewBuilder()

	if builder == nil {
		t.Error("Expected builder to be non-nil")
	}
}

func TestBuilderNewArray(t *testing.T) {
	builder := NewBuilder()

	// Test with no options
	array := builder.NewArray(nil)
	if array == nil {
		t.Fatal("Expected array to be non-nil")
	}

	if array.Type != "" {
		t.Errorf("Expected empty type, got %q", array.Type)
	}

	if array.Values == nil {
		t.Error("Expected values to be initialized")
	}
}

func TestBuilderNewArrayWithOptions(t *testing.T) {
	builder := NewBuilder()

	opts := &ArrayOptions{
		ValuesType: "byte",
		Values:     []interface{}{1, 2, 3, 4},
	}

	array := builder.NewArray(opts)
	if array == nil {
		t.Fatal("Expected array to be non-nil")
	}

	if array.Type != "byte" {
		t.Errorf("Expected type 'byte', got %q", array.Type)
	}

	if len(array.Values) != 4 {
		t.Errorf("Expected 4 values, got %d", len(array.Values))
	}
}

func TestBuilderNewObject(t *testing.T) {
	builder := NewBuilder()

	// Test with no options
	object := builder.NewObject(nil)
	if object == nil {
		t.Fatal("Expected object to be non-nil")
	}

	if object.ClassDesc == nil {
		t.Error("Expected class description to be set")
	}

	if object.ClassData == nil {
		t.Error("Expected class data to be initialized")
	}
}

func TestBuilderNewObjectWithOptions(t *testing.T) {
	builder := NewBuilder()

	opts := &ObjectOptions{
		Data: []interface{}{[]interface{}{"int", 42}},
	}

	object := builder.NewObject(opts)
	if object == nil {
		t.Fatal("Expected object to be non-nil")
	}

	if len(object.ClassData) != 1 {
		t.Errorf("Expected 1 data item, got %d", len(object.ClassData))
	}
}

func TestBuilderNewClass(t *testing.T) {
	builder := NewBuilder()

	// Test with no options
	class := builder.NewClass(nil)
	if class == nil {
		t.Fatal("Expected class to be non-nil")
	}

	if class.ClassName != nil {
		t.Error("Expected class name to be nil")
	}

	if class.SerialVersion != 0 {
		t.Errorf("Expected serial version 0, got %d", class.SerialVersion)
	}

	if class.Flags != 0x02 { // SC_SERIALIZABLE
		t.Errorf("Expected flags 0x02, got 0x%02x", class.Flags)
	}

	if class.Fields == nil {
		t.Error("Expected fields to be initialized")
	}

	if class.ClassAnnotation == nil {
		t.Error("Expected class annotation to be set")
	}

	if class.SuperClass == nil {
		t.Error("Expected super class to be set")
	}
}

func TestBuilderNewClassWithOptions(t *testing.T) {
	builder := NewBuilder()

	opts := &ClassOptions{
		Name:   "java.lang.String",
		Serial: 0x1234567890ABCDEF,
		Flags:  0x04, // SC_EXTERNALIZABLE
		Fields: []FieldData{
			{Type: "int", Name: "value"},
			{Type: "object", Name: "next", FieldType: "java.lang.String"},
		},
	}

	class := builder.NewClass(opts)
	if class == nil {
		t.Fatal("Expected class to be non-nil")
	}

	if class.ClassName == nil {
		t.Fatal("Expected class name to be set")
	}

	if class.ClassName.Contents != "java.lang.String" {
		t.Errorf("Expected class name 'java.lang.String', got %q", class.ClassName.Contents)
	}

	if class.SerialVersion != 0x1234567890ABCDEF {
		t.Errorf("Expected serial version 0x1234567890ABCDEF, got 0x%x", class.SerialVersion)
	}

	if class.Flags != 0x04 {
		t.Errorf("Expected flags 0x04, got 0x%02x", class.Flags)
	}

	if len(class.Fields) != 2 {
		t.Errorf("Expected 2 fields, got %d", len(class.Fields))
	}

	// Check first field
	field1 := class.Fields[0]
	if field1.Type != "int" {
		t.Errorf("Expected field 1 type 'int', got %q", field1.Type)
	}

	if field1.Name == nil {
		t.Fatal("Expected field 1 name to be set")
	}

	if field1.Name.Contents != "value" {
		t.Errorf("Expected field 1 name 'value', got %q", field1.Name.Contents)
	}

	// Check second field
	field2 := class.Fields[1]
	if field2.Type != "object" {
		t.Errorf("Expected field 2 type 'object', got %q", field2.Type)
	}

	if field2.Name == nil {
		t.Fatal("Expected field 2 name to be set")
	}

	if field2.Name.Contents != "next" {
		t.Errorf("Expected field 2 name 'next', got %q", field2.Name.Contents)
	}

	if field2.FieldType == nil {
		t.Fatal("Expected field 2 field type to be set")
	}

	if field2.FieldType.Contents != "java.lang.String" {
		t.Errorf("Expected field 2 field type 'java.lang.String', got %q", field2.FieldType.Contents)
	}
}

func TestBuilderNewClassWithSuperClass(t *testing.T) {
	builder := NewBuilder()

	opts := &ClassOptions{
		Name:       "SubClass",
		SuperClass: model.NewUtf(nil, "SuperClass"),
	}

	class := builder.NewClass(opts)
	if class == nil {
		t.Fatal("Expected class to be non-nil")
	}

	if class.SuperClass == nil {
		t.Fatal("Expected super class to be set")
	}

	if class.SuperClass.Description == nil {
		t.Fatal("Expected super class description to be set")
	}

	utf, ok := class.SuperClass.Description.(*model.Utf)
	if !ok {
		t.Fatal("Expected super class description to be Utf")
	}

	if utf.Contents != "SuperClass" {
		t.Errorf("Expected super class 'SuperClass', got %q", utf.Contents)
	}
}
