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
    if err := ne.EnumClassDesc.Decode(reader, stream); err != nil {
        // Be tolerant for empty/minimal input
        if err == io.EOF || err == io.ErrUnexpectedEOF {
            return nil
        }
        return &DecodeError{Message: "failed to decode enum class description"}
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
	// TODO: Implement new enum encoding
	return []byte{}, nil
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
