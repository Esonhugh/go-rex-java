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
	fmt.Println("References containing java/lang/Class or [[B:")
	for i, ref := range stream.References {
		if utf, ok := ref.(*model.Utf); ok {
			if strings.Contains(utf.Contents, "java/lang/Class") || utf.Contents == "[[B" {
				fmt.Printf("Ref[%d]: %s\n", i, utf.Contents)
			}
		}
	}
}
