package model

import (
	"encoding/binary"
	"github.com/esonhugh/go-rex-java/constants"
	"io"
)

// ProxyClassDesc represents a proxy class description in Java serialization
type ProxyClassDesc struct {
	*BaseElement
	Interfaces []*Utf
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

	return nil
}

// Encode serializes the ProxyClassDesc to bytes
func (pcd *ProxyClassDesc) Encode() ([]byte, error) {
	// TODO: Implement proxy class description encoding
	return []byte{}, nil
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
