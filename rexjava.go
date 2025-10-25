// Package rexjava provides Java serialization stream parsing capabilities
package rexjava

import (
	"github.com/esonhugh/go-rex-java/serialization"
)

// Version returns the library version
func Version() string {
	return serialization.Version
}

// NewStream creates a new Java serialization stream
func NewStream() *serialization.Stream {
	return serialization.NewStream()
}

// NewBuilder creates a new builder for constructing Java serialized contents
func NewBuilder() *serialization.Builder {
	return serialization.NewBuilder()
}
