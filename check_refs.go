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

	fmt.Printf("Hibernate1 parsed: %d contents, %d references\n", len(stream.Contents), len(stream.References))

	// 查找 "[[B" 字符串在引用表中的位置
	targetContent := "[[B"
	for i, ref := range stream.References {
		if utf, ok := ref.(*model.Utf); ok {
			if utf.Contents == targetContent {
				fmt.Printf("Found \"[[B\" at reference index %d\n", i)

				// 检查这个引用是否在内容中出现过多次
				count := 0
				for _, content := range stream.Contents {
					if content == ref {
						count++
					}
				}
				fmt.Printf("Reference[%d] appears %d times in contents\n", i, count)
				break
			}
		}
	}

	if len(stream.References) > 19 {
		fmt.Printf("Reference[19]: %s\n", stream.References[19].String())
	}
}
