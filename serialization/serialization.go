package serialization

import (
	"bytes"
	"github.com/esonhugh/go-rex-java/serialization/model"
)

// Version represents the library version
const Version = "1.0.0"

// Stream represents the main entry point for Java serialization operations
type Stream struct {
	*model.Stream
}

// NewStream creates a new Stream instance
func NewStream() *Stream {
	return &Stream{
		Stream: model.NewStream(),
	}
}

// DecodeStream deserializes a Stream from bytes
func DecodeStream(data []byte) (*Stream, error) {
	reader := bytes.NewReader(data)
	stream := NewStream()
	err := stream.Stream.Decode(reader)
	if err != nil {
		return nil, err
	}
	return stream, nil
}

// Decode deserializes a Java serialization stream from the given reader
func (s *Stream) Decode(reader interface{}) error {
	// This is a placeholder - actual implementation would depend on the reader type
	return nil
}

// Encode serializes the stream to bytes
func (s *Stream) Encode() ([]byte, error) {
	return s.Stream.Encode()
}

// String returns a string representation of the stream
func (s *Stream) String() string {
	return s.Stream.String()
}
