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
	if _, err := io.ReadFull(reader, lengthBytes); err != nil {
		return &DecodeError{Message: "failed to read UTF length"}
	}

	u.Length = binary.BigEndian.Uint16(lengthBytes)
	u.Stream = stream

	// Read contents
	if u.Length == 0 {
		u.Contents = ""
	} else {
		contentsBytes := make([]byte, u.Length)
		n, err := io.ReadFull(reader, contentsBytes)
		if err != nil {
			// Be tolerant: if we couldn't read all bytes, use what we got
			if n > 0 {
				u.Contents = string(contentsBytes[:n])
				u.Length = uint16(n)
				return nil
			}
			// If we got EOF/UnexpectedEOF and length was set, return empty string
			if err == io.EOF || err == io.ErrUnexpectedEOF {
				u.Contents = ""
				u.Length = 0
				return nil
			}
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
