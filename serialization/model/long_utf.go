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
	if _, err := io.ReadFull(reader, lengthBytes); err != nil {
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			lu.Length = 0
			lu.Contents = ""
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
		if _, err := io.ReadFull(reader, contentsBytes); err != nil {
			if err == io.EOF || err == io.ErrUnexpectedEOF {
				// Use partial content if available
				if len(contentsBytes) > 0 {
					lu.Contents = string(contentsBytes[:len(contentsBytes)])
					lu.Length = uint64(len(contentsBytes))
				} else {
					lu.Contents = ""
					lu.Length = 0
				}
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
	encoded := make([]byte, 0, 8+len(lu.Contents))

	// Encode length (8 bytes, uint64)
	lengthBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(lengthBytes, uint64(len(lu.Contents)))
	encoded = append(encoded, lengthBytes...)

	// Encode contents
	if len(lu.Contents) > 0 {
		encoded = append(encoded, []byte(lu.Contents)...)
	}

	return encoded, nil
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
