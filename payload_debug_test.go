package rexjava

import (
	"testing"
	
	"github.com/esonhugh/go-rex-java/serialization/model"
)

func TestDebugPayload(t *testing.T) {
	// Test with BeanShell1 payload that's failing
	err := model.DebugPayloadFromFile("ysoserial_payloads.json", "BeanShell1")
	if err != nil {
		t.Logf("Debug analysis: %v", err)
	}
}

func TestDebugPayloadDetailed(t *testing.T) {
	// Detailed analysis around position 205 where error occurs
	err := model.DebugPayloadDetailed("ysoserial_payloads.json", "BeanShell1", 205)
	if err != nil {
		t.Logf("Detailed analysis: %v", err)
	}
}

func TestDebugClick1(t *testing.T) {
	err := model.DebugPayloadFromFile("ysoserial_payloads.json", "Click1")
	if err != nil {
		t.Logf("Debug analysis: %v", err)
	}
}

