package model

import (
	"encoding/binary"
	"io"
)

// LongUtf represents a long UTF-8 string in Java serialization
type LongUtf struct {
	*BaseElement
	Length   uint64
	Contents string
}

// NewLongUtf creates a new LongUtf instance
func NewLongUtf(stream *Stream) *LongUtf {
	return &LongUtf{
		BaseElement: NewBaseElement(stream),
		Length:      0,
		Contents:    "",
	}
}

// Decode deserializes a LongUtf from the given reader
func (lu *LongUtf) Decode(reader io.Reader, stream *Stream) error {
	lu.Stream = stream

	// Read length (8 bytes, uint64)
	lengthBytes := make([]byte, 8)
    n, err := reader.Read(lengthBytes)
    if err != nil || n != 8 {
        if err == io.EOF || err == io.ErrUnexpectedEOF {
            return nil
        }
        return &DecodeError{Message: "failed to read long UTF length"}
    }

	lu.Length = binary.BigEndian.Uint64(lengthBytes)

	// Read contents
	if lu.Length == 0 {
		lu.Contents = ""
	} else {
		contentsBytes := make([]byte, lu.Length)
        n, err := reader.Read(contentsBytes)
        if err != nil || n != int(lu.Length) {
            if err == io.EOF || err == io.ErrUnexpectedEOF {
                return nil
            }
            return &DecodeError{Message: "failed to read long UTF contents"}
        }
		lu.Contents = string(contentsBytes)
	}

	return nil
}

// Encode serializes the LongUtf to bytes
func (lu *LongUtf) Encode() ([]byte, error) {
	// TODO: Implement long UTF encoding
	return []byte{}, nil
}

// String returns a string representation of the LongUtf
func (lu *LongUtf) String() string {
	if lu == nil {
		return "LongUtf(nil)"
	}
	if lu.Contents == "" {
		return "LongUtf"
	}
	return lu.Contents
}

// marshalLongUtf marshals a LongUtf to JSON-friendly format
func marshalLongUtf(lu *LongUtf) interface{} {
	if lu == nil {
		return nil
	}
	return map[string]interface{}{
		"type":     "LongUtf",
		"length":   lu.Length,
		"contents": lu.Contents,
	}
}
