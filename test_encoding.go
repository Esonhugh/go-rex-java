package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/esonhugh/go-rex-java/serialization/model"
)

func main() {
	data, _ := os.ReadFile("ysoserial_payloads.json")
	var payloads struct {
		None map[string]struct {
			Status string `json:"status"`
			Bytes  string `json:"bytes"`
		} `json:"none"`
	}
	json.Unmarshal(data, &payloads)

	payloadBytes, _ := base64.StdEncoding.DecodeString(payloads.None["Hibernate1"].Bytes)
	stream := model.NewStream()
	reader := strings.NewReader(string(payloadBytes))
	stream.Decode(reader)

	encoded, err := stream.Encode()
	if err != nil {
		fmt.Printf("Encode error: %v\n", err)
		return
	}

	fmt.Printf("Hibernate1: original %d bytes, encoded %d bytes\n", len(payloadBytes), len(encoded))

	// Find first difference
	minLen := len(payloadBytes)
	if len(encoded) < minLen {
		minLen = len(encoded)
	}

	for i := 0; i < minLen; i++ {
		if payloadBytes[i] != encoded[i] {
			fmt.Printf("First difference at 0x%x: orig 0x%02x, enc 0x%02x\n", i, payloadBytes[i], encoded[i])
			break
		}
	}
}
