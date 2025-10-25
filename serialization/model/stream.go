package model

import (
	"encoding/binary"
	"fmt"
	"github.com/esonhugh/go-rex-java/constants"
	"io"
)

// Stream represents a Java serialization stream
type Stream struct {
	*BaseElement
	Magic      uint16
	Version    uint16
	Contents   []Element
	References []Element
}

// NewStream creates a new Stream instance
func NewStream() *Stream {
	return &Stream{
		BaseElement: NewBaseElement(nil),
		Magic:       constants.StreamMagic,
		Version:     constants.StreamVersion,
		Contents:    make([]Element, 0),
		References:  make([]Element, 0),
	}
}

// Decode deserializes a Stream from the given reader
func (s *Stream) Decode(reader io.Reader) error {
	// Decode magic number
	if err := s.decodeMagic(reader); err != nil {
		return err
	}

	// Decode version
	if err := s.decodeVersion(reader); err != nil {
		return err
	}

	// Decode contents until EOF
	for {
		content, err := DecodeElement(reader, s)
		if err != nil {
			// Check if it's EOF
			if err == io.EOF {
				break
			}
			return err
		}
		s.Contents = append(s.Contents, content)
	}

	return nil
}

// Encode serializes the Stream to bytes
func (s *Stream) Encode() ([]byte, error) {
	encoded := make([]byte, 0, 1024)

	// Encode magic number
	magicBytes := make([]byte, constants.SIZE_SHORT)
	binary.BigEndian.PutUint16(magicBytes, s.Magic)
	encoded = append(encoded, magicBytes...)

	// Encode version
	versionBytes := make([]byte, constants.SIZE_SHORT)
	binary.BigEndian.PutUint16(versionBytes, s.Version)
	encoded = append(encoded, versionBytes...)

	// Encode contents
	for _, content := range s.Contents {
		contentBytes, err := EncodeElement(content)
		if err != nil {
			return nil, err
		}
		encoded = append(encoded, contentBytes...)
	}

	return encoded, nil
}

// AddReference adds an element to the references array
func (s *Stream) AddReference(element Element) {
	s.References = append(s.References, element)
}

// String returns a string representation of the Stream
func (s *Stream) String() string {
	result := fmt.Sprintf("@magic: 0x%x\n", s.Magic)
	result += fmt.Sprintf("@version: %d\n", s.Version)
	result += "@contents: [\n"
	for _, content := range s.Contents {
		result += fmt.Sprintf("  %s\n", content.String())
	}
	result += "]\n"
	result += "@references: [\n"
	for i, ref := range s.References {
		result += fmt.Sprintf("  [0x%x] %s\n", i+constants.BASE_WIRE_HANDLE, ref.String())
	}
	result += "]\n"
	return result
}

// DecodeMagic deserializes the magic stream value
func (s *Stream) DecodeMagic(reader io.Reader) error {
	return s.decodeMagic(reader)
}

// DecodeVersion deserializes the version stream
func (s *Stream) DecodeVersion(reader io.Reader) error {
	return s.decodeVersion(reader)
}

// decodeMagic deserializes the magic stream value
func (s *Stream) decodeMagic(reader io.Reader) error {
	magicBytes := make([]byte, constants.SIZE_SHORT)
	n, err := reader.Read(magicBytes)
	if err != nil || n != 2 {
		return &DecodeError{Message: "failed to read magic number"}
	}

	magic := binary.BigEndian.Uint16(magicBytes)
	if magic != constants.StreamMagic {
		return &DecodeError{Message: "invalid magic number"}
	}

	s.Magic = magic
	return nil
}

// decodeVersion deserializes the version stream
func (s *Stream) decodeVersion(reader io.Reader) error {
	versionBytes := make([]byte, constants.SIZE_SHORT)
	n, err := reader.Read(versionBytes)
	if err != nil || n != 2 {
		return &DecodeError{Message: "failed to read version"}
	}

	version := binary.BigEndian.Uint16(versionBytes)
	if version != constants.StreamVersion {
		return &DecodeError{Message: "invalid version"}
	}

	s.Version = version
	return nil
}
