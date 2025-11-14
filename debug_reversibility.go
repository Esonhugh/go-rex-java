package rexjava

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"

	"github.com/esonhugh/go-rex-java/serialization/model"
)

func main() {
	// Read CommonsBeanutils1 payload
	data, err := ioutil.ReadFile("ysoserial_payloads.json")
	if err != nil {
		fmt.Printf("Failed to read file: %v\n", err)
		return
	}

	var payloads struct {
		None map[string]struct {
			Bytes string `json:"bytes"`
		} `json:"none"`
	}

	if err := json.Unmarshal(data, &payloads); err != nil {
		fmt.Printf("Failed to parse JSON: %v\n", err)
		return
	}

	payloadBytes, _ := base64.StdEncoding.DecodeString(payloads.None["CommonsBeanutils1"].Bytes)

	fmt.Printf("Original payload: %d bytes\n", len(payloadBytes))

	// First decode
	reader1 := bytes.NewReader(payloadBytes)
	stream1 := model.NewStream()
	if err := stream1.Decode(reader1); err != nil {
		fmt.Printf("Failed to decode: %v\n", err)
		return
	}

	fmt.Printf("First decode: %d contents, %d references\n", len(stream1.Contents), len(stream1.References))

	// First encode
	encoded1, err := stream1.Encode()
	if err != nil {
		fmt.Printf("Failed to encode: %v\n", err)
		return
	}

	fmt.Printf("First encode: %d bytes\n", len(encoded1))

	// Second decode
	reader2 := bytes.NewReader(encoded1)
	stream2 := model.NewStream()
	if err := stream2.Decode(reader2); err != nil {
		fmt.Printf("Failed to decode re-encoded: %v\n", err)
		return
	}

	fmt.Printf("Second decode: %d contents, %d references\n", len(stream2.Contents), len(stream2.References))

	// Compare references
	fmt.Printf("Reference comparison:\n")
	minRefs := len(stream1.References)
	if len(stream2.References) < minRefs {
		minRefs = len(stream2.References)
	}

	for i := 0; i < minRefs; i++ {
		ref1 := stream1.References[i]
		ref2 := stream2.References[i]
		if ref1 != ref2 {
			fmt.Printf("  Reference[%d] differs: %s vs %s\n", i, ref1.String(), ref2.String())
		}
	}

	if len(stream1.References) != len(stream2.References) {
		fmt.Printf("Reference count mismatch: %d vs %d\n", len(stream1.References), len(stream2.References))
	}

	// Second encode
	encoded2, err := stream2.Encode()
	if err != nil {
		fmt.Printf("Failed to re-encode: %v\n", err)
		return
	}

	fmt.Printf("Second encode: %d bytes\n", len(encoded2))

	// Compare encodings
	if len(encoded1) != len(encoded2) {
		fmt.Printf("Encoding length mismatch: %d vs %d\n", len(encoded1), len(encoded2))

		// Find first difference
		minLen := len(encoded1)
		if len(encoded2) < minLen {
			minLen = len(encoded2)
		}

		for i := 0; i < minLen; i++ {
			if encoded1[i] != encoded2[i] {
				fmt.Printf("First difference at position 0x%x: 0x%02x vs 0x%02x\n", i, encoded1[i], encoded2[i])
				break
			}
		}
	} else if !bytes.Equal(encoded1, encoded2) {
		fmt.Printf("Encodings are different but same length\n")
	} else {
		fmt.Printf("Encodings are identical - test should pass\n")
	}
}
