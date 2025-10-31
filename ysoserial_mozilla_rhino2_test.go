package rexjava

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/esonhugh/go-rex-java/serialization/model"
)

// TestMozillaRhino2Decode specifically tests MozillaRhino2 payload
func TestMozillaRhino2Decode(t *testing.T) {
	// Read the JSON file
	data, err := os.ReadFile("ysoserial_payloads.json")
	if err != nil {
		t.Fatalf("Failed to read ysoserial_payloads.json: %v", err)
	}

	var payloads PayloadsData
	if err := json.Unmarshal(data, &payloads); err != nil {
		t.Fatalf("Failed to parse JSON: %v", err)
	}

	// Get MozillaRhino2 payload
	payloadInfo, exists := payloads.None["MozillaRhino2"]
	if !exists {
		t.Fatal("MozillaRhino2 payload not found")
	}

	if payloadInfo.Status == "unsupported" || payloadInfo.Bytes == "" {
		t.Skip("MozillaRhino2 is unsupported or empty")
	}

	// Test base64 decoding
	bytesData, err := base64.StdEncoding.DecodeString(payloadInfo.Bytes)
	if err != nil {
		t.Fatalf("Failed to decode base64: %v", err)
	}

	// Verify minimum size
	if len(bytesData) < 4 {
		t.Errorf("Payload too small: %d bytes", len(bytesData))
		return
	}

	// Check magic number
	if bytesData[0] != 0xac || bytesData[1] != 0xed {
		t.Errorf("Invalid magic number: 0x%02x%02x", bytesData[0], bytesData[1])
		return
	}

	// Try to parse
	stream := model.NewStream()
	reader := strings.NewReader(string(bytesData))

	decodeErr := stream.Decode(reader)
	if decodeErr != nil {
		t.Fatalf("Failed to decode MozillaRhino2: %v", decodeErr)
	}

	// Verify stream structure
	if stream.Magic != 0xaced {
		t.Errorf("Invalid magic: 0x%x", stream.Magic)
	}

	if len(stream.Contents) == 0 {
		t.Error("No contents found")
	}

	// Test JSON marshaling
	jsonData, err := json.Marshal(stream)
	if err != nil {
		t.Fatalf("Failed to marshal to JSON: %v", err)
	}

	// Verify JSON is not empty
	if len(jsonData) == 0 {
		t.Error("Empty JSON output")
	}

	t.Logf("MozillaRhino2 successfully parsed: %d bytes, %d contents, %d references, JSON size: %d bytes",
		len(bytesData), len(stream.Contents), len(stream.References), len(jsonData))
}

