package rexjava

import (
	"testing"
)

func TestVersion(t *testing.T) {
	version := Version()
	if version == "" {
		t.Error("Expected version to be non-empty")
	}
}

func TestNewStream(t *testing.T) {
	stream := NewStream()

	if stream == nil {
		t.Fatal("Expected stream to be non-nil")
	}
}

func TestNewBuilder(t *testing.T) {
	builder := NewBuilder()

	if builder == nil {
		t.Fatal("Expected builder to be non-nil")
	}
}
