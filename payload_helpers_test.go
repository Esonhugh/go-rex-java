package rexjava

import (
	"encoding/json"
	"fmt"
	"os"
	"testing"
)

// ExtendedPayloadsData includes payload categories beyond "none"
type ExtendedPayloadsData struct {
	None       map[string]PayloadInfo `json:"none"`
	Bash       map[string]PayloadInfo `json:"bash"`
	Cmd        map[string]PayloadInfo `json:"cmd"`
	Powershell map[string]PayloadInfo `json:"powershell"`
}

// loadExtendedPayloads reads ysoserial_payloads.json and returns the parsed structure
func loadExtendedPayloads(t *testing.T) ExtendedPayloadsData {
	data, err := os.ReadFile("ysoserial_payloads.json")
	if err != nil {
		t.Fatalf("Failed to read ysoserial_payloads.json: %v", err)
	}

	var payloads ExtendedPayloadsData
	if err := json.Unmarshal(data, &payloads); err != nil {
		t.Fatalf("Failed to parse ysoserial_payloads.json: %v", err)
	}

	return payloads
}

// findPayload searches across all payload categories for the given name
// and returns the PayloadInfo, the category name, and whether it was found.
func findPayload(payloads ExtendedPayloadsData, name string) (PayloadInfo, string, bool) {
	categories := []struct {
		label string
		data  map[string]PayloadInfo
	}{
		{"none", payloads.None},
		{"bash", payloads.Bash},
		{"cmd", payloads.Cmd},
		{"powershell", payloads.Powershell},
	}

	for _, cat := range categories {
		if cat.data == nil {
			continue
		}
		if info, ok := cat.data[name]; ok && info.Bytes != "" {
			return info, cat.label, true
		}
	}

	return PayloadInfo{}, "", false
}

// mustFindPayload wraps findPayload and fails the test immediately when the payload isn't found.
func mustFindPayload(t *testing.T, payloads ExtendedPayloadsData, name string) PayloadInfo {
	if info, _, ok := findPayload(payloads, name); ok {
		return info
	}
	t.Fatalf("Payload %s not found in ysoserial_payloads.json", name)
	return PayloadInfo{}
}

// describePayloadLocation returns a human readable string for the payload location
func describePayloadLocation(payloads ExtendedPayloadsData, name string) string {
	if _, category, ok := findPayload(payloads, name); ok {
		return category
	}
	return fmt.Sprintf("%s not found", name)
}


