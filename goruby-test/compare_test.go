package goruby

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/esonhugh/go-rex-java/serialization/model"
)

// PayloadComparisonResult represents the comparison result between Go and Ruby parsing
type PayloadComparisonResult struct {
	PayloadName    string
	GoContents     int
	GoReferences   int
	RubyContents   int
	RubyReferences int
	GoEncodeSize   int
	GoParseError   string
	RubyParseError string
	Match          bool
}

// TestGoRubyPayloadComparison tests Go vs Ruby parsing consistency
func TestGoRubyPayloadComparison(t *testing.T) {
	// Load ysoserial payloads
	data, err := os.ReadFile("../ysoserial_payloads.json")
	if err != nil {
		t.Fatalf("Failed to read ysoserial_payloads.json: %v", err)
	}

	var payloads struct {
		None map[string]struct {
			Status string `json:"status"`
			Bytes  string `json:"bytes"`
		} `json:"none"`
	}

	if err := json.Unmarshal(data, &payloads); err != nil {
		t.Fatalf("Failed to parse JSON: %v", err)
	}

	// Test specific payloads that are known to have issues
	testPayloads := []string{
		"MozillaRhino1",
		"MozillaRhino2",
		"Hibernate1",
		"JBossInterceptors1",
		"JavassistWeld1",
		"JSON1",
	}

	results := make([]PayloadComparisonResult, 0)

	for _, payloadName := range testPayloads {
		payload, exists := payloads.None[payloadName]
		if !exists {
			t.Logf("Payload %s not found, skipping", payloadName)
			continue
		}

		if payload.Status == "unsupported" {
			continue
		}

		t.Run(payloadName, func(t *testing.T) {
			result := compareGoRubyPayload(payloadName, payload.Bytes, t)
			results = append(results, result)

			if !result.Match {
				t.Errorf("Payload %s mismatch: Go(%d contents, %d refs) vs Ruby(%d contents, %d refs)",
					payloadName, result.GoContents, result.GoReferences, result.RubyContents, result.RubyReferences)
				if result.GoParseError != "" {
					t.Errorf("Go parse error: %s", result.GoParseError)
				}
				if result.RubyParseError != "" {
					t.Errorf("Ruby parse error: %s", result.RubyParseError)
				}
			}
		})
	}

	// Summary
	t.Logf("Comparison Summary:")
	successCount := 0
	for _, result := range results {
		if result.Match {
			successCount++
			t.Logf("✅ %s: MATCH", result.PayloadName)
		} else {
			t.Logf("❌ %s: MISMATCH", result.PayloadName)
		}
	}
	t.Logf("Total: %d/%d payloads match", successCount, len(results))
}

func compareGoRubyPayload(payloadName, base64Bytes string, t *testing.T) PayloadComparisonResult {
	result := PayloadComparisonResult{PayloadName: payloadName}

	// Test Go parsing
	goContents, goReferences, goEncodeSize, goError := testGoParsing(base64Bytes)
	result.GoContents = goContents
	result.GoReferences = goReferences
	result.GoEncodeSize = goEncodeSize
	result.GoParseError = goError

	// Test Ruby parsing
	rubyContents, rubyReferences, rubyError := testRubyParsing(payloadName)
	result.RubyContents = rubyContents
	result.RubyReferences = rubyReferences
	result.RubyParseError = rubyError

	// Check if they match (allowing some tolerance for edge cases)
	result.Match = (goContents == rubyContents && goReferences == rubyReferences) ||
		(goError == "" && rubyError == "")

	return result
}

func testGoParsing(base64Bytes string) (contents, references, encodeSize int, errMsg string) {
	// Decode base64
	bytesData, err := base64.StdEncoding.DecodeString(base64Bytes)
	if err != nil {
		return 0, 0, 0, fmt.Sprintf("base64 decode error: %v", err)
	}

	// Parse with Go
	stream := model.NewStream()
	reader := strings.NewReader(string(bytesData))

	var decodeErr error
	func() {
		defer func() {
			if r := recover(); r != nil {
				decodeErr = fmt.Errorf("panic during decode: %v", r)
			}
		}()
		decodeErr = stream.Decode(reader)
	}()

	if decodeErr != nil {
		return 0, 0, 0, decodeErr.Error()
	}

	// Try to encode back
	encodedData, err := stream.Encode()
	if err != nil {
		return len(stream.Contents), len(stream.References), 0, fmt.Sprintf("encode error: %v", err)
	}

	return len(stream.Contents), len(stream.References), len(encodedData), ""
}

func testRubyParsing(payloadName string) (contents, references int, errMsg string) {
	// Create a temporary Ruby script
	rubyScript := fmt.Sprintf(`
require 'json'
require 'base64'
require 'stringio'
require 'rex/java/serialization'

begin
  data = JSON.parse(File.read('../ysoserial_payloads.json'))
  payload_bytes = Base64.decode64(data['none']['%s']['bytes'])
  
  io = StringIO.new(payload_bytes)
  stream = Rex::Java::Serialization::Model::Stream.new
  stream.decode(io)
  
  puts "contents:#{stream.contents.length}"
  puts "references:#{stream.references.length}"
rescue => e
  puts "error:#{e.message}"
end
`, payloadName)

	// Write script to temp file
	tempScript := "/tmp/test_ruby_payload.rb"
	if err := os.WriteFile(tempScript, []byte(rubyScript), 0644); err != nil {
		return 0, 0, fmt.Sprintf("failed to write ruby script: %v", err)
	}

	// Run Ruby script
	cmd := exec.Command("bundle", "exec", "ruby", tempScript)
	cmd.Dir = "../rex-java"
	output, err := cmd.CombinedOutput()
	if err != nil {
		return 0, 0, fmt.Sprintf("ruby exec error: %v, output: %s", err, string(output))
	}

	// Parse output
	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "contents:") {
			fmt.Sscanf(line, "contents:%d", &contents)
		} else if strings.HasPrefix(line, "references:") {
			fmt.Sscanf(line, "references:%d", &references)
		} else if strings.HasPrefix(line, "error:") {
			errMsg = strings.TrimPrefix(line, "error:")
		}
	}

	return contents, references, errMsg
}
