package model

import (
	"encoding/binary"
	"encoding/json"
	"io"
)

// Utf represents a UTF-8 string in Java serialization
type Utf struct {
	*BaseElement
	Length   uint16
	Contents string
}

// NewUtf creates a new Utf instance
func NewUtf(stream *Stream, contents string) *Utf {
	return &Utf{
		BaseElement: NewBaseElement(stream),
		Length:      uint16(len(contents)),
		Contents:    contents,
	}
}

// Decode deserializes a Utf from the given reader
func (u *Utf) Decode(reader io.Reader, stream *Stream) error {
	// Read length (2 bytes)
	lengthBytes := make([]byte, 2)
	n, err := reader.Read(lengthBytes)
	if err != nil || n != 2 {
		return &DecodeError{Message: "failed to read UTF length"}
	}

	u.Length = binary.BigEndian.Uint16(lengthBytes)
	u.Stream = stream

	// Read contents
	if u.Length == 0 {
		u.Contents = ""
	} else {
		contentsBytes := make([]byte, u.Length)
		n, err := reader.Read(contentsBytes)
		if err != nil || n != int(u.Length) {
			return &DecodeError{Message: "failed to read UTF contents"}
		}
		u.Contents = string(contentsBytes)
	}

	return nil
}

// Encode serializes the Utf to bytes
func (u *Utf) Encode() ([]byte, error) {
	encoded := make([]byte, 2+len(u.Contents))
	binary.BigEndian.PutUint16(encoded, u.Length)
	copy(encoded[2:], u.Contents)
	return encoded, nil
}

// String returns the contents as string representation
func (u *Utf) String() string {
	return u.Contents
}

// marshalUtf marshals a Utf to JSON-friendly format
func marshalUtf(u *Utf) interface{} {
	if u == nil {
		return nil
	}
	return map[string]interface{}{
		"type":     "Utf",
		"length":   u.Length,
		"contents": u.Contents,
	}
}

// MarshalJSON marshals Utf to JSON
func (u *Utf) MarshalJSON() ([]byte, error) {
	return json.Marshal(marshalUtf(u))
}
