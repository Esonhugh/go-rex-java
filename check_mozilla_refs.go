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
	payloadBytes, _ := base64.StdEncoding.DecodeString(payloads.None["MozillaRhino1"].Bytes)
	stream := model.NewStream()
	reader := strings.NewReader(string(payloadBytes))
	stream.Decode(reader)
	fmt.Printf("MozillaRhino1: %d contents, %d references\n", len(stream.Contents), len(stream.References))

	// Check the maximum reference index we need to handle
	maxIndex := 0
	for i := range stream.Contents {
		if ref, ok := stream.Contents[i].(*model.Reference); ok {
			refIndex := int(ref.Handle - 0x7e0000)
			if refIndex > maxIndex {
				maxIndex = refIndex
			}
		}
	}
	fmt.Printf("Maximum reference index needed: %d\n", maxIndex)
	fmt.Printf("Actual references available: %d\n", len(stream.References))

	// Check if the strange handle exists in our parsed stream
	strangeHandle := uint32(0xeead7400)
	strangeRefIndex := int(strangeHandle - 0x7e0000)
	fmt.Printf("Strange handle 0x%x corresponds to ref index %d\n", strangeHandle, strangeRefIndex)
	fmt.Printf("Do we have enough references? %v\n", strangeRefIndex < len(stream.References))
}
