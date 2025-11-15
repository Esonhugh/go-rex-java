package model

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"

	"github.com/esonhugh/go-rex-java/constants"
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
	// OmitFlagsAndFields indicates that flags and field_count were omitted in the original stream
	// and should be omitted during encoding to match the original format
	OmitFlagsAndFields bool
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
	debugLog("NewClassDesc.Decode: Decoded class name: %q (length=%d)", ncd.ClassName.Contents, len(ncd.ClassName.Contents))

	// Decode serial version (8 bytes)
	serialBytes := make([]byte, constants.SIZE_LONG)
	if _, err := io.ReadFull(reader, serialBytes); err != nil {
		// Be tolerant: if we can't read serial version, use 0 as default
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			ncd.SerialVersion = 0
		} else {
			return &DecodeError{Message: "failed to read serial version"}
		}
	} else {
		ncd.SerialVersion = binary.BigEndian.Uint64(serialBytes)
	}
	debugLog("NewClassDesc.Decode: Decoded SerialVersionUID: 0x%016x", ncd.SerialVersion)

	// Add reference to stream
	if stream != nil {
		stream.AddReference(ncd)
		debugLog("NewClassDesc.Decode: Added to stream.References at index %d", len(stream.References)-1)
	}

	// Decode flags (1 byte)
	// Check if the next byte is TC_BLOCKDATA (0x77), which indicates ClassAnnotation starts
	// This can happen if flags and field_count are omitted or in a special format
	var err error
	var peekBuf [1]byte
	debugLog("NewClassDesc.Decode: About to read flags byte after SerialVersionUID (0x%016x)", ncd.SerialVersion)
	if _, err = io.ReadFull(reader, peekBuf[:]); err != nil {
		// Be tolerant: if we can't read flags, use default
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			ncd.Flags = constants.SC_SERIALIZABLE
			// Use default field count of 0
			ncd.Fields = make([]*Field, 0)
			// Decode class annotation
			ncd.ClassAnnotation = NewAnnotation(stream)
			if err := ncd.ClassAnnotation.Decode(reader, stream); err != nil {
				return err
			}
			// Decode super class
			ncd.SuperClass = NewClassDescInstance(stream)
			if err := ncd.SuperClass.Decode(reader, stream); err != nil {
				// Be tolerant: if we can't read super class, use null reference
				if err == io.EOF || err == io.ErrUnexpectedEOF {
					ncd.SuperClass.Description = NewNullReference(stream)
				} else {
					return err
				}
			}
			return nil
		}
		return &DecodeError{Message: "failed to read flags"}
	}

	// Check if peeked byte is TC_BLOCKDATA (ClassAnnotation starts immediately)
	debugLog("NewClassDesc.Decode: Peeked byte after SerialVersionUID: 0x%02x", peekBuf[0])
	if peekBuf[0] == constants.TC_BLOCKDATA || peekBuf[0] == constants.TC_BLOCKDATALONG {
		// ClassAnnotation starts immediately, flags and field_count are omitted
		// Use default flags and field_count = 0
		ncd.Flags = constants.SC_SERIALIZABLE
		ncd.Fields = make([]*Field, 0)
		ncd.OmitFlagsAndFields = true // Mark that flags and field_count were omitted
		debugLog("NewClassDesc.Decode: ✅ Detected TC_BLOCKDATA (0x%02x) at flags position (first check), omitting flags and field_count", peekBuf[0])

		// The peeked byte is the start of ClassAnnotation, so we need to put it back
		// Use a MultiReader to put the byte back
		reader = io.MultiReader(bytes.NewReader(peekBuf[:]), reader)

		// Decode class annotation
		ncd.ClassAnnotation = NewAnnotation(stream)
		debugLog("NewClassDesc.Decode: Decoding ClassAnnotation (OmitFlagsAndFields=true, SerialVersionUID=0x%016x)", ncd.SerialVersion)
		if err := ncd.ClassAnnotation.Decode(reader, stream); err != nil {
			debugLog("NewClassDesc.Decode: Failed to decode ClassAnnotation: %v", err)
			return err
		}
		debugLog("NewClassDesc.Decode: ClassAnnotation decoded with %d elements", len(ncd.ClassAnnotation.Contents))
		// Decode super class
		ncd.SuperClass = NewClassDescInstance(stream)
		if err := ncd.SuperClass.Decode(reader, stream); err != nil {
			// Be tolerant: if we can't read super class, use null reference
			if err == io.EOF || err == io.ErrUnexpectedEOF {
				ncd.SuperClass.Description = NewNullReference(stream)
			} else {
				return err
			}
		}
		return nil
	}

	// Normal case: the byte is flags
	// But check if it's actually TC_BLOCKDATA (indicating flags/field_count are omitted)
	// This can happen if the check above didn't catch it (edge case)
	if peekBuf[0] == constants.TC_BLOCKDATA || peekBuf[0] == constants.TC_BLOCKDATALONG {
		// This is actually TC_BLOCKDATA, not flags!
		// Flags and field_count are omitted, ClassAnnotation starts immediately
		debugLog("NewClassDesc.Decode: ⚠️  Found TC_BLOCKDATA at flags position in normal path, switching to OmitFlagsAndFields=true")
		ncd.Flags = constants.SC_SERIALIZABLE
		ncd.Fields = make([]*Field, 0)
		ncd.OmitFlagsAndFields = true

		// Put the byte back and decode ClassAnnotation
		reader = io.MultiReader(bytes.NewReader(peekBuf[:]), reader)
		ncd.ClassAnnotation = NewAnnotation(stream)
		debugLog("NewClassDesc.Decode: Decoding ClassAnnotation (OmitFlagsAndFields=true, SerialVersionUID=0x%016x)", ncd.SerialVersion)
		if err := ncd.ClassAnnotation.Decode(reader, stream); err != nil {
			debugLog("NewClassDesc.Decode: Failed to decode ClassAnnotation: %v", err)
			return err
		}
		debugLog("NewClassDesc.Decode: ClassAnnotation decoded with %d elements", len(ncd.ClassAnnotation.Contents))
		// Decode super class
		ncd.SuperClass = NewClassDescInstance(stream)
		if err := ncd.SuperClass.Decode(reader, stream); err != nil {
			// Be tolerant: if we can't read super class, use null reference
			if err == io.EOF || err == io.ErrUnexpectedEOF {
				ncd.SuperClass.Description = NewNullReference(stream)
			} else {
				return err
			}
		}
		return nil
	}

	ncd.Flags = peekBuf[0]

	// Decode field count (2 bytes)
	fieldCountBytes := make([]byte, constants.SIZE_SHORT)
	var fieldCount uint16
	if _, err := io.ReadFull(reader, fieldCountBytes); err != nil {
		// Be tolerant: if we can't read field count, assume 0 fields
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			fieldCount = 0
		} else {
			return &DecodeError{Message: "failed to read field count"}
		}
	} else {
		fieldCount = binary.BigEndian.Uint16(fieldCountBytes)
	}

	// Decode fields
	ncd.Fields = make([]*Field, 0, fieldCount)
	for i := uint16(0); i < fieldCount; i++ {
		field := NewField(stream)
		if err := field.Decode(reader, stream); err != nil {
			// Be tolerant: if we hit EOF while decoding fields, stop and continue
			if err == io.EOF || err == io.ErrUnexpectedEOF {
				break
			}
			return err
		}
		ncd.Fields = append(ncd.Fields, field)
	}

	// Decode class annotation
	ncd.ClassAnnotation = NewAnnotation(stream)
	debugLog("NewClassDesc.Decode: Decoding ClassAnnotation (normal path)")
	if err := ncd.ClassAnnotation.Decode(reader, stream); err != nil {
		debugLog("NewClassDesc.Decode: Failed to decode ClassAnnotation: %v", err)
		return err
	}
	debugLog("NewClassDesc.Decode: ClassAnnotation decoded with %d elements", len(ncd.ClassAnnotation.Contents))
	// Decode super class
	ncd.SuperClass = NewClassDescInstance(stream)
	if err := ncd.SuperClass.Decode(reader, stream); err != nil {
		// Be tolerant: if we can't read super class, use null reference
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			ncd.SuperClass.Description = NewNullReference(stream)
		} else {
			return err
		}
	}

	return nil
}

// Encode serializes the NewClassDesc to bytes
func (ncd *NewClassDesc) Encode() ([]byte, error) {
	return ncd.EncodeWithContext(nil)
}

// EncodeWithContext serializes the NewClassDesc with a shared encode context
func (ncd *NewClassDesc) EncodeWithContext(ctx *EncodeContext) ([]byte, error) {
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

	// If flags and field_count were omitted in the original stream, omit them during encoding
	if !ncd.OmitFlagsAndFields {
		// Encode flags (1 byte)
		encoded = append(encoded, ncd.Flags)

		// Encode field count (2 bytes)
		fieldCountBytes := make([]byte, constants.SIZE_SHORT)
		binary.BigEndian.PutUint16(fieldCountBytes, uint16(len(ncd.Fields)))
		encoded = append(encoded, fieldCountBytes...)

		// Encode fields
		for _, field := range ncd.Fields {
			fieldBytes, err := field.EncodeWithContext(ctx)
			if err != nil {
				return nil, err
			}
			encoded = append(encoded, fieldBytes...)
		}
	} else {
		// If OmitFlagsAndFields is true, skip flags, field_count, and fields
		// ClassAnnotation will start immediately after SerialVersionUID
		debugLog("NewClassDesc.EncodeWithContext: OmitFlagsAndFields=true, skipping flags and field_count")
	}

	// Encode class annotation
	if ncd.ClassAnnotation != nil {
		annotationBytes, err := ncd.ClassAnnotation.EncodeWithContext(ctx)
		if err != nil {
			return nil, err
		}
		encoded = append(encoded, annotationBytes...)
	}

	// Encode super class using ClassDesc.EncodeWithContext
	if ncd.SuperClass != nil {
		superClassBytes, err := ncd.SuperClass.EncodeWithContext(ctx)
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
