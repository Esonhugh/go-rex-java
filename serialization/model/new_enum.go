package model

import (
	"io"
)

// NewEnum represents a new enum in Java serialization
type NewEnum struct {
	*BaseElement
	EnumClassDesc    *ClassDesc
	EnumConstantName *Utf
}

// NewNewEnum creates a new NewEnum instance
func NewNewEnum(stream *Stream) *NewEnum {
	return &NewEnum{
		BaseElement:      NewBaseElement(stream),
		EnumClassDesc:    nil,
		EnumConstantName: nil,
	}
}

// Decode deserializes a NewEnum from the given reader
func (ne *NewEnum) Decode(reader io.Reader, stream *Stream) error {
	ne.Stream = stream

	// Decode enum class description (ClassDesc)
	ne.EnumClassDesc = NewClassDescInstance(stream)
	debugLog("NewEnum.Decode: Starting to decode enumClassDesc")
	if err := ne.EnumClassDesc.Decode(reader, stream); err != nil {
		debugLog("NewEnum.Decode: Failed to decode enumClassDesc: %v", err)
		// Be tolerant for empty/minimal input
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			return nil
		}
		return &DecodeError{Message: "failed to decode enum class description"}
	}
	debugLog("NewEnum.Decode: Successfully decoded enumClassDesc")
	if newClassDesc, ok := ne.EnumClassDesc.Description.(*NewClassDesc); ok {
		debugLog("NewEnum.Decode: EnumClassDesc is NewClassDesc, SerialVersionUID=0x%016x, OmitFlagsAndFields=%v",
			newClassDesc.SerialVersion, newClassDesc.OmitFlagsAndFields)
		if newClassDesc.ClassAnnotation != nil {
			debugLog("NewEnum.Decode: EnumClassDesc has ClassAnnotation with %d elements", len(newClassDesc.ClassAnnotation.Contents))
		}
	}

	// Add reference to stream
	if stream != nil {
		stream.AddReference(ne)
	}

	// Decode enum constant name (TC_STRING)
	enumConstantElem, err := DecodeElement(reader, stream)
	if err != nil {
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			return nil
		}
		return &DecodeError{Message: "failed to decode enum constant name"}
	}

	if utf, ok := enumConstantElem.(*Utf); ok {
		ne.EnumConstantName = utf
	} else {
		return &DecodeError{Message: "enum constant name is not a UTF string"}
	}

	return nil
}

// Encode serializes the NewEnum to bytes
func (ne *NewEnum) Encode() ([]byte, error) {
	return ne.EncodeWithContext(nil)
}

// EncodeWithContext serializes the NewEnum with a shared encode context
func (ne *NewEnum) EncodeWithContext(ctx *EncodeContext) ([]byte, error) {
	encoded := make([]byte, 0, 256)

	// Encode enum class description (ClassDesc)
	if ne.EnumClassDesc == nil {
		return nil, &EncodeError{Message: "enum class description is nil"}
	}

	var classDescBytes []byte
	var err error
	if ctx != nil {
		classDescBytes, err = ne.EnumClassDesc.EncodeWithContext(ctx)
	} else {
		classDescBytes, err = ne.EnumClassDesc.Encode()
	}
	if err != nil {
		return nil, &EncodeError{Message: "failed to encode enum class description: " + err.Error()}
	}
	encoded = append(encoded, classDescBytes...)

	// Encode enum constant name (TC_STRING)
	if ne.EnumConstantName == nil {
		return nil, &EncodeError{Message: "enum constant name is nil"}
	}

	var constantNameBytes []byte
	if ctx != nil {
		constantNameBytes, err = EncodeElementWithContext(ne.EnumConstantName, ctx)
	} else {
		constantNameBytes, err = EncodeElement(ne.EnumConstantName)
	}
	if err != nil {
		return nil, &EncodeError{Message: "failed to encode enum constant name: " + err.Error()}
	}
	encoded = append(encoded, constantNameBytes...)

	return encoded, nil
}

// String returns a string representation of the NewEnum
func (ne *NewEnum) String() string {
	return "NewEnum"
}

// marshalNewEnum marshals a NewEnum to JSON-friendly format
func marshalNewEnum(ne *NewEnum) interface{} {
	if ne == nil {
		return nil
	}
	return map[string]interface{}{
		"type":               "NewEnum",
		"enum_class_desc":    marshalClassDesc(ne.EnumClassDesc),
		"enum_constant_name": marshalUtf(ne.EnumConstantName),
	}
}
