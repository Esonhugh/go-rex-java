package model

import (
	"encoding/binary"
	"github.com/esonhugh/go-rex-java/constants"
	"io"
)

// ProxyClassDesc represents a proxy class description in Java serialization
type ProxyClassDesc struct {
	*BaseElement
	Interfaces      []*Utf
	ClassAnnotation *Annotation
	SuperClass      *ClassDesc
}

// NewProxyClassDesc creates a new ProxyClassDesc instance
func NewProxyClassDesc(stream *Stream) *ProxyClassDesc {
	return &ProxyClassDesc{
		BaseElement: NewBaseElement(stream),
		Interfaces:  make([]*Utf, 0),
	}
}

// Decode deserializes a ProxyClassDesc from the given reader
func (pcd *ProxyClassDesc) Decode(reader io.Reader, stream *Stream) error {
	pcd.Stream = stream

	// Read interface count (4 bytes, int32)
	countBytes := make([]byte, constants.SIZE_INT)
    if _, err := io.ReadFull(reader, countBytes); err != nil {
        if err == io.EOF || err == io.ErrUnexpectedEOF {
            return nil
        }
        return &DecodeError{Message: "failed to read proxy class description interface count"}
    }
	count := int32(binary.BigEndian.Uint32(countBytes))

	// Add reference to stream
	if stream != nil {
		stream.AddReference(pcd)
	}

	// Read interfaces (each is a UTF string, not a TC_STRING element)
	pcd.Interfaces = make([]*Utf, 0, count)
	for i := int32(0); i < count; i++ {
		utf := NewUtf(stream, "")
		if err := utf.Decode(reader, stream); err != nil {
			return &DecodeError{Message: "failed to decode proxy interface"}
		}
		pcd.Interfaces = append(pcd.Interfaces, utf)
	}

	// Decode class annotation
	pcd.ClassAnnotation = NewAnnotation(stream)
	if err := pcd.ClassAnnotation.Decode(reader, stream); err != nil {
		return &DecodeError{Message: "failed to decode proxy class annotation"}
	}

	// Decode super class
	pcd.SuperClass = NewClassDescInstance(stream)
	if err := pcd.SuperClass.Decode(reader, stream); err != nil {
		return &DecodeError{Message: "failed to decode proxy super class"}
	}

	return nil
}

// Encode serializes the ProxyClassDesc to bytes
func (pcd *ProxyClassDesc) Encode() ([]byte, error) {
	if pcd.ClassAnnotation == nil || pcd.SuperClass == nil {
		return nil, &EncodeError{Message: "proxy class description is incomplete"}
	}

	encoded := make([]byte, 0, 256)

	// Encode interface count (4 bytes, int32)
	countBytes := make([]byte, constants.SIZE_INT)
	binary.BigEndian.PutUint32(countBytes, uint32(len(pcd.Interfaces)))
	encoded = append(encoded, countBytes...)

	// Encode interfaces (each is a UTF string, not a TC_STRING element)
	for _, iface := range pcd.Interfaces {
		ifaceBytes, err := iface.Encode()
		if err != nil {
			return nil, err
		}
		encoded = append(encoded, ifaceBytes...)
	}

	// Encode class annotation
	annBytes, err := pcd.ClassAnnotation.Encode()
	if err != nil {
		return nil, err
	}
	encoded = append(encoded, annBytes...)

	// Encode super class
	superBytes, err := pcd.SuperClass.Encode()
	if err != nil {
		return nil, err
	}
	encoded = append(encoded, superBytes...)

	return encoded, nil
}

// String returns a string representation of the ProxyClassDesc
func (pcd *ProxyClassDesc) String() string {
	return "ProxyClassDesc"
}

// marshalProxyClassDesc marshals a ProxyClassDesc to JSON-friendly format
func marshalProxyClassDesc(pcd *ProxyClassDesc) interface{} {
	if pcd == nil {
		return nil
	}

	interfaces := make([]interface{}, len(pcd.Interfaces))
	for i, iface := range pcd.Interfaces {
		interfaces[i] = marshalUtf(iface)
	}

	return map[string]interface{}{
		"type":       "ProxyClassDesc",
		"interfaces": interfaces,
	}
}
