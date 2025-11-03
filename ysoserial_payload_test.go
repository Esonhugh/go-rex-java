package rexjava

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/esonhugh/go-rex-java/serialization/model"
)

// PayloadInfo represents information about a ysoserial payload
type PayloadInfo struct {
	Status       string `json:"status"`
	LengthOffset []int  `json:"lengthOffset,omitempty"`
	BufferOffset []int  `json:"bufferOffset,omitempty"`
	Bytes        string `json:"bytes"`
}

// PayloadsData represents the structure of ysoserial_payloads.json
type PayloadsData struct {
	None map[string]PayloadInfo `json:"none"`
}

// TestYsoserialPayloadsStructure tests that the JSON file structure is correct
func TestYsoserialPayloadsStructure(t *testing.T) {
	// Read the JSON file
	data, err := os.ReadFile("ysoserial_payloads.json")
	if err != nil {
		t.Fatalf("Failed to read ysoserial_payloads.json: %v", err)
	}

	var payloads PayloadsData
	if err := json.Unmarshal(data, &payloads); err != nil {
		t.Fatalf("Failed to parse JSON: %v", err)
	}

	// Count payloads
	totalPayloads := 0
	validPayloads := 0
	for payloadName, payloadInfo := range payloads.None {
		totalPayloads++
		if payloadInfo.Status != "unsupported" && payloadInfo.Bytes != "" {
			validPayloads++
			t.Logf("Found valid payload: %s (status: %s)", payloadName, payloadInfo.Status)
		}
	}

	t.Logf("Total payloads: %d, Valid payloads: %d", totalPayloads, validPayloads)
}

// TestYsoserialPayloadsDecode tests decoding base64 payloads
func TestYsoserialPayloadsDecode(t *testing.T) {
	// Read the JSON file
	data, err := os.ReadFile("ysoserial_payloads.json")
	if err != nil {
		t.Fatalf("Failed to read ysoserial_payloads.json: %v", err)
	}

	var payloads PayloadsData
	if err := json.Unmarshal(data, &payloads); err != nil {
		t.Fatalf("Failed to parse JSON: %v", err)
	}

	// Test base64 decoding for all payloads
	testCount := 0
	successCount := 0
	maxTests := 100

	for payloadName, payloadInfo := range payloads.None {
		// Skip unsupported payloads
		if payloadInfo.Status == "unsupported" || payloadInfo.Bytes == "" {
			continue
		}

		if testCount >= maxTests {
			break
		}

		testCount++
		t.Run(payloadName, func(t *testing.T) {
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
			if bytesData[0] == 0xac && bytesData[1] == 0xed {
				t.Logf("Valid Java serialization magic number: 0x%02x%02x", bytesData[0], bytesData[1])
				successCount++
			} else {
				t.Logf("Invalid magic number: 0x%02x%02x", bytesData[0], bytesData[1])
			}

			// Try to parse if magic number is valid
			if bytesData[0] == 0xac && bytesData[1] == 0xed {
				stream := model.NewStream()
				reader := strings.NewReader(string(bytesData))

				var decodeErr error
				decodeErr = stream.Decode(reader)

				if decodeErr != nil {
					t.Logf("Decode failed (may contain unsupported elements): %v", decodeErr)
					t.FailNow()
				} else {
					// Test JSON marshal
					jsonData, err := json.Marshal(stream)
					if err != nil {
						t.Errorf("Failed to marshal to JSON: %v", err)
					} else {
						t.Logf("Successfully parsed and marshaled: %d contents, %d references, JSON size: %d bytes",
							len(stream.Contents), len(stream.References), len(jsonData))
					}
				}

				jd, _ := json.MarshalIndent(stream, "", "  ")
				// try encode back
				encodedData, err := stream.Encode()
				if err != nil {
					// 	t.Errorf("Failed to encode: %v, json: %v", err, string(jd))
					t.FailNow()
				} else {
					t.Logf("Successfully encoded: %d bytes", len(encodedData))
				}
				if !bytes.Equal(encodedData, bytesData) {
					t.Errorf("Encoded data mismatch, json data: %v", string(jd))
					t.FailNow()
				} else {
					t.Logf("Successfully encoded and decoded back")
				}

			}
		})
	}

	t.Logf("Total tested: %d, With valid magic: %d", testCount, successCount)
}

// testPayload tests parsing a single payload
func testPayload(t *testing.T, name string, info PayloadInfo) bool {
	// Decode base64 bytes
	bytesData, err := base64.StdEncoding.DecodeString(info.Bytes)
	if err != nil {
		t.Errorf("Failed to decode base64 for %s: %v", name, err)
		return false
	}

	// Check minimum size (should have magic number and version)
	if len(bytesData) < 4 {
		t.Errorf("Payload %s is too small: %d bytes", name, len(bytesData))
		return false
	}

	// Check magic number
	if bytesData[0] != 0xac || bytesData[1] != 0xed {
		t.Logf("Payload %s doesn't have valid magic number: 0x%02x%02x", name, bytesData[0], bytesData[1])
		return false
	}

	// Create a reader from the bytes
	reader := strings.NewReader(string(bytesData))

	// Create and decode stream with recover to catch stack overflow
	var stream *model.Stream
	var decodeErr error
	func() {
		defer func() {
			if r := recover(); r != nil {
				decodeErr = fmt.Errorf("panic during decode: %v", r)
			}
		}()
		stream = model.NewStream()
		decodeErr = stream.Decode(reader)
	}()

	if decodeErr != nil {
		// Some payloads might not be standard serialization format
		t.Logf("Failed to decode %s: %v (this might be expected)", name, decodeErr)
		return false
	}

	// Verify stream structure
	if stream.Magic != 0xaced {
		t.Errorf("Invalid magic number for %s: 0x%x", name, stream.Magic)
		return false
	}

	// Check if we have contents
	if len(stream.Contents) == 0 {
		t.Logf("No contents found for %s", name)
		return false
	}

	// Try to marshal to JSON (test our JSON marshal functionality)
	jsonData, err := json.Marshal(stream)
	if err != nil {
		t.Errorf("Failed to marshal %s to JSON: %v", name, err)
		return false
	}

	// Verify JSON is not empty
	if len(jsonData) == 0 {
		t.Errorf("Empty JSON output for %s", name)
		return false
	}

	t.Logf("Successfully parsed %s: %d contents, %d references, JSON size: %d bytes",
		name, len(stream.Contents), len(stream.References), len(jsonData))

	return true
}

// TestSpecificPayloads tests specific well-known payloads
func TestSpecificPayloads(t *testing.T) {
	data, err := os.ReadFile("ysoserial_payloads.json")
	if err != nil {
		t.Fatalf("Failed to read ysoserial_payloads.json: %v", err)
	}

	var payloads PayloadsData
	if err := json.Unmarshal(data, &payloads); err != nil {
		t.Fatalf("Failed to parse JSON: %v", err)
	}

	// Test a few specific payloads
	testCases := []string{
		"BeanShell1",
		"Click1",
		"CommonsCollections1",
		"CommonsBeanutils1",
	}

	for _, payloadName := range testCases {
		payloadInfo, exists := payloads.None[payloadName]
		if !exists {
			t.Logf("Payload %s not found, skipping", payloadName)
			continue
		}

		if payloadInfo.Status == "unsupported" || payloadInfo.Bytes == "" {
			t.Logf("Payload %s is unsupported or empty, skipping", payloadName)
			continue
		}

		t.Run(payloadName, func(t *testing.T) {
			bytesData, err := base64.StdEncoding.DecodeString(payloadInfo.Bytes)
			if err != nil {
				t.Fatalf("Failed to decode base64: %v", err)
			}

			stream := model.NewStream()
			reader := strings.NewReader(string(bytesData))

			var decodeErr error
			decodeErr = stream.Decode(reader)
			if decodeErr != nil {
				t.Logf("Failed to decode stream: %v (may contain unsupported elements)", decodeErr)
				// t.Skip("Skipping payload with unsupported elements")
				t.FailNow()
				return
			}

			// Verify basic structure
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

			// Parse JSON back to verify structure
			var jsonResult map[string]interface{}
			if err := json.Unmarshal(jsonData, &jsonResult); err != nil {
				t.Fatalf("Failed to unmarshal JSON: %v", err)
			}

			if jsonResult["type"] != "Stream" {
				t.Errorf("Expected type 'Stream', got '%v'", jsonResult["type"])
			}

			t.Logf("Payload %s: %d bytes, %d contents, %d references",
				payloadName, len(bytesData), len(stream.Contents), len(stream.References))
		})
	}
}

// TestPayloadStructure validates the structure of parsed payloads
func TestPayloadStructure(t *testing.T) {
	data, err := os.ReadFile("ysoserial_payloads.json")
	if err != nil {
		t.Fatalf("Failed to read ysoserial_payloads.json: %v", err)
	}

	var payloads PayloadsData
	if err := json.Unmarshal(data, &payloads); err != nil {
		t.Fatalf("Failed to parse JSON: %v", err)
	}

	// Find first valid payload
	var testPayload PayloadInfo
	var testName string
	for name, payload := range payloads.None {
		if payload.Status == "dynamic" && payload.Bytes != "" {
			testPayload = payload
			testName = name
			break
		}
	}

	if testName == "" {
		t.Skip("No valid payload found for structure test")
	}

	// Decode and parse
	bytesData, err := base64.StdEncoding.DecodeString(testPayload.Bytes)
	if err != nil {
		t.Fatalf("Failed to decode base64: %v", err)
	}

	stream := model.NewStream()
	reader := strings.NewReader(string(bytesData))

	var decodeErr error
	decodeErr = stream.Decode(reader)

	if decodeErr != nil {
		t.Logf("Failed to decode: %v (may contain unsupported elements)", decodeErr)
		t.Errorf("Skipping payload with unsupported elements")
		t.FailNow()
		return
	}

	// Print detailed structure
	fmt.Printf("\n=== Payload: %s ===\n", testName)
	fmt.Printf("Magic: 0x%x\n", stream.Magic)
	fmt.Printf("Version: %d\n", stream.Version)
	fmt.Printf("Contents count: %d\n", len(stream.Contents))
	fmt.Printf("References count: %d\n", len(stream.References))

	// Print first few contents types
	for i, content := range stream.Contents {
		if i >= 5 {
			fmt.Printf("... (showing first 5 of %d)\n", len(stream.Contents))
			break
		}
		fmt.Printf("  Contents[%d]: %s\n", i, content.String())
	}

	// Print references
	for i, ref := range stream.References {
		// if i >= 5 {
		//	fmt.Printf("... (showing first 5 of %d)\n", len(stream.References))
		//	break
		// }
		handle := 0x7e0000 + i
		fmt.Printf("  References[%d] (handle 0x%x): %s\n", i, handle, ref.String())
	}
}
