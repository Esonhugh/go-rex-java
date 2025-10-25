package serialization

// DecodeError represents an error during deserialization
type DecodeError struct {
	Message string
}

func (e *DecodeError) Error() string {
	return e.Message
}

// EncodeError represents an error during serialization
type EncodeError struct {
	Message string
}

func (e *EncodeError) Error() string {
	return e.Message
}
