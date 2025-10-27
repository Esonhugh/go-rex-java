package model

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"github.com/esonhugh/go-rex-java/constants"
	"io"
)

// NewClassDesc represents a new class description in Java serialization
type NewClassDesc struct {
	*BaseElement
	ClassName       *Utf
	SerialVersion   uint64
	Flags           uint8
	Fields          []*Field
	ClassAnnotation *Annotation
	SuperClass      *ClassDesc
}

// NewNewClassDesc creates a new NewClassDesc instance
func NewNewClassDesc(stream *Stream) *NewClassDesc {
	return &NewClassDesc{
		BaseElement:     NewBaseElement(stream),
		ClassName:       nil,
		SerialVersion:   0,
		Flags:           constants.SC_SERIALIZABLE,
		Fields:          make([]*Field, 0),
		ClassAnnotation: nil,
		SuperClass:      nil,
	}
}

// Decode deserializes a NewClassDesc from the given reader
func (ncd *NewClassDesc) Decode(reader io.Reader, stream *Stream) error {
	ncd.Stream = stream

	// Decode class name (direct UTF, not a TC_STRING element)
	ncd.ClassName = NewUtf(stream, "")
	if err := ncd.ClassName.Decode(reader, stream); err != nil {
		return fmt.Errorf("failed to decode class name: %w", err)
	}

	// Decode serial version (8 bytes)
	serialBytes := make([]byte, constants.SIZE_LONG)
	n, err := reader.Read(serialBytes)
	if err != nil || n != 8 {
		return &DecodeError{Message: "failed to read serial version"}
	}
	ncd.SerialVersion = binary.BigEndian.Uint64(serialBytes)

	// Add reference to stream
	if stream != nil {
		stream.AddReference(ncd)
	}

	// Decode flags (1 byte)
	flagsBytes := make([]byte, constants.SIZE_BYTE)
	n, err = reader.Read(flagsBytes)
	if err != nil || n != 1 {
		return &DecodeError{Message: "failed to read flags"}
	}
	ncd.Flags = flagsBytes[0]

	// Decode field count (2 bytes)
	fieldCountBytes := make([]byte, constants.SIZE_SHORT)
	n, err = reader.Read(fieldCountBytes)
	if err != nil || n != 2 {
		return &DecodeError{Message: "failed to read field count"}
	}
	fieldCount := binary.BigEndian.Uint16(fieldCountBytes)

	// Decode fields
	ncd.Fields = make([]*Field, 0, fieldCount)
	for i := uint16(0); i < fieldCount; i++ {
		field := NewField(stream)
		if err := field.Decode(reader, stream); err != nil {
			return err
		}
		ncd.Fields = append(ncd.Fields, field)
	}

	// Decode class annotation
	ncd.ClassAnnotation = NewAnnotation(stream)
	if err := ncd.ClassAnnotation.Decode(reader, stream); err != nil {
		return err
	}

	// Decode super class
	ncd.SuperClass = NewClassDescInstance(stream)
	if err := ncd.SuperClass.Decode(reader, stream); err != nil {
		return err
	}

	return nil
}

// Encode serializes the NewClassDesc to bytes
func (ncd *NewClassDesc) Encode() ([]byte, error) {
	encoded := make([]byte, 0, 1024)

	// Encode class name (direct UTF, not a TC_STRING element)
	if ncd.ClassName != nil {
		classNameBytes, err := ncd.ClassName.Encode()
		if err != nil {
			return nil, err
		}
		encoded = append(encoded, classNameBytes...)
	} else {
		// Empty class name
		encoded = append(encoded, 0, 0)
	}

	// Encode serial version (8 bytes)
	serialBytes := make([]byte, constants.SIZE_LONG)
	binary.BigEndian.PutUint64(serialBytes, ncd.SerialVersion)
	encoded = append(encoded, serialBytes...)

	// Encode flags (1 byte)
	encoded = append(encoded, ncd.Flags)

	// Encode field count (2 bytes)
	fieldCountBytes := make([]byte, constants.SIZE_SHORT)
	binary.BigEndian.PutUint16(fieldCountBytes, uint16(len(ncd.Fields)))
	encoded = append(encoded, fieldCountBytes...)

	// Encode fields
	for _, field := range ncd.Fields {
		fieldBytes, err := field.Encode()
		if err != nil {
			return nil, err
		}
		encoded = append(encoded, fieldBytes...)
	}

	// Encode class annotation
	if ncd.ClassAnnotation != nil {
		annotationBytes, err := ncd.ClassAnnotation.Encode()
		if err != nil {
			return nil, err
		}
		encoded = append(encoded, annotationBytes...)
	}

	// Encode super class
	if ncd.SuperClass != nil {
		superClassBytes, err := ncd.SuperClass.Encode()
		if err != nil {
			return nil, err
		}
		encoded = append(encoded, superClassBytes...)
	}

	return encoded, nil
}

// marshalNewClassDesc marshals a NewClassDesc to JSON-friendly format
func marshalNewClassDesc(ncd *NewClassDesc) interface{} {
	result := map[string]interface{}{
		"type":           "NewClassDesc",
		"class_name":     marshalUtf(ncd.ClassName),
		"serial_version": ncd.SerialVersion,
		"flags":          ncd.Flags,
		"fields":         marshalFields(ncd.Fields),
	}

	if ncd.ClassAnnotation != nil {
		result["class_annotation"] = marshalAnnotation(ncd.ClassAnnotation)
	}
	if ncd.SuperClass != nil {
		result["super_class"] = marshalClassDesc(ncd.SuperClass)
	}

	return result
}

// marshalFields marshals a slice of fields
func marshalFields(fields []*Field) []interface{} {
	result := make([]interface{}, 0, len(fields))
	for _, field := range fields {
		result = append(result, marshalField(field))
	}
	return result
}

// MarshalJSON marshals NewClassDesc to JSON
func (ncd *NewClassDesc) MarshalJSON() ([]byte, error) {
	return json.Marshal(marshalNewClassDesc(ncd))
}

// String returns a string representation of the NewClassDesc
func (ncd *NewClassDesc) String() string {
	if ncd.ClassName != nil {
		return ncd.ClassName.String()
	}
	return "NewClassDesc"
}
