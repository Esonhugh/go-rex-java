package model

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"

	"github.com/esonhugh/go-rex-java/constants"
)

// Reference represents an object reference in Java serialization
type Reference struct {
	*BaseElement
	Handle uint32
}

// NewReference creates a new Reference instance
func NewReference(stream *Stream, handle uint32) *Reference {
	return &Reference{
		BaseElement: NewBaseElement(stream),
		Handle:      handle,
	}
}

// Decode deserializes a Reference from the given reader
func (r *Reference) Decode(reader io.Reader, stream *Stream) error {
	handleBytes := make([]byte, 4)
	if _, err := io.ReadFull(reader, handleBytes); err != nil {
		return &DecodeError{Message: "failed to read reference handle"}
	}

	r.Handle = binary.BigEndian.Uint32(handleBytes)
	r.Stream = stream

	// Validate reference handle for ysoserial compatibility
	// Some payloads contain references to non-existent objects
	refIndex := int(r.Handle - constants.BASE_WIRE_HANDLE)
	if refIndex < 0 || (stream != nil && refIndex >= len(stream.References)) {
		// Invalid reference - this can happen in specially crafted payloads
		// For compatibility, we allow this but mark it as potentially invalid
		// The encoding logic will need to handle this case
	}

	return nil
}

// Encode serializes the Reference to bytes
func (r *Reference) Encode() ([]byte, error) {
	encoded := make([]byte, 4)
	binary.BigEndian.PutUint32(encoded, r.Handle)
	return encoded, nil
}

// String returns a string representation of the Reference
func (r *Reference) String() string {
	return "Reference"
}

// marshalReference marshals a Reference to JSON-friendly format
func marshalReference(r *Reference) interface{} {
	if r == nil {
		return nil
	}
	return map[string]interface{}{
		"type":   "Reference",
		"handle": fmt.Sprintf("0x%x", r.Handle),
	}
}

// MarshalJSON marshals Reference to JSON
func (r *Reference) MarshalJSON() ([]byte, error) {
	return json.Marshal(marshalReference(r))
}
