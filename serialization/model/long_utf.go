package model

import (
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
	// TODO: Implement long UTF decoding
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
