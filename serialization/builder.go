package serialization

import (
	"github.com/esonhugh/go-rex-java/constants"
	"github.com/esonhugh/go-rex-java/serialization/model"
)

// Builder provides a builder to help in the construction of Java serialized contents
type Builder struct{}

// NewBuilder creates a new Builder instance
func NewBuilder() *Builder {
	return &Builder{}
}

// NewArray creates a NewArray with the given options
func (b *Builder) NewArray(opts *ArrayOptions) *model.NewArray {
	array := model.NewNewArray(nil)

	if opts != nil {
		if opts.Description != nil {
			array.ArrayDescription = model.NewClassDescInstance(nil)
			array.ArrayDescription.Description = opts.Description
		} else if opts.ClassOpts != nil {
			classDesc := b.NewClass(opts.ClassOpts)
			array.ArrayDescription = model.NewClassDescInstance(nil)
			array.ArrayDescription.Description = classDesc
		}

		if opts.ValuesType != "" {
			array.Type = opts.ValuesType
		}
		if opts.Values != nil {
			array.Values = opts.Values
		}
	}

	return array
}

// NewObject creates a NewObject with the given options
func (b *Builder) NewObject(opts *ObjectOptions) *model.NewObject {
	object := model.NewNewObject(nil)

	// Always set a default ClassDesc
	object.ClassDesc = model.NewClassDescInstance(nil)

	if opts != nil {
		if opts.Description != nil {
			object.ClassDesc.Description = opts.Description
		} else if opts.ClassOpts != nil {
			classDesc := b.NewClass(opts.ClassOpts)
			object.ClassDesc.Description = classDesc
		}

		if opts.Data != nil {
			// Convert []interface{} to []*model.PrimitiveValue
			primitiveData := make([]*model.PrimitiveValue, len(opts.Data))
			for i, data := range opts.Data {
				primitiveData[i] = model.NewPrimitiveValue(model.Object, data)
			}
			object.ClassData = primitiveData
		}
	}

	return object
}

// NewClass creates a NewClassDesc with the given options
func (b *Builder) NewClass(opts *ClassOptions) *model.NewClassDesc {
	classDesc := model.NewNewClassDesc(nil)

	// Set default annotations
	classDesc.ClassAnnotation = model.NewAnnotation(nil)
	classDesc.ClassAnnotation.Contents = []model.Element{
		model.NewNullReference(nil),
		model.NewEndBlockData(nil),
	}

	// Set super class
	classDesc.SuperClass = model.NewClassDescInstance(nil)
	classDesc.SuperClass.Description = model.NewNullReference(nil)

	if opts != nil {
		if opts.Name != "" {
			classDesc.ClassName = model.NewUtf(nil, opts.Name)
		}
		if opts.Serial != 0 {
			classDesc.SerialVersion = opts.Serial
		}
		if opts.Flags != 0 {
			classDesc.Flags = opts.Flags
		} else {
			classDesc.Flags = constants.SC_SERIALIZABLE
		}

		// Process fields
		if opts.Fields != nil {
			classDesc.Fields = make([]*model.Field, 0, len(opts.Fields))
			for _, fieldData := range opts.Fields {
				field := model.NewField(nil)
				field.Type = fieldData.Type
				field.Name = model.NewUtf(nil, fieldData.Name)
				if fieldData.FieldType != "" {
					field.FieldType = model.NewUtf(nil, fieldData.FieldType)
				}
				classDesc.Fields = append(classDesc.Fields, field)
			}
		}

		// Override super class if provided
		if opts.SuperClass != nil {
			classDesc.SuperClass.Description = opts.SuperClass
		}
	}

	return classDesc
}

// ArrayOptions contains options for creating a NewArray
type ArrayOptions struct {
	Description *model.NewClassDesc
	ClassOpts   *ClassOptions
	ValuesType  string
	Values      []interface{}
}

// ObjectOptions contains options for creating a NewObject
type ObjectOptions struct {
	Description *model.NewClassDesc
	ClassOpts   *ClassOptions
	Data        []interface{}
}

// ClassOptions contains options for creating a NewClassDesc
type ClassOptions struct {
	Name        string
	Serial      uint64
	Flags       uint8
	Fields      []FieldData
	Annotations []model.Element
	SuperClass  model.Element
}

// FieldData represents field information for class creation
type FieldData struct {
	Type      model.ObjectType
	Name      string
	FieldType string
}
