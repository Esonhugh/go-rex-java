package main

import (
	"encoding/json"
	"fmt"
	"github.com/esonhugh/go-rex-java/serialization"
	"io/ioutil"
	"log"
)

func main() {
	fmt.Println("Testing abc.ser with Go rex-java library...")

	data, err := ioutil.ReadFile("./main/abc.ser")
	if err != nil {
		log.Fatalf("Failed to read abc.ser: %v", err)
	}
	fmt.Printf("File size: %d bytes\n", len(data))

	stream, err := serialization.DecodeStream(data)
	if err != nil {
		fmt.Printf("Stream parsing failed: %v\n", err)
		fmt.Println("Go test failed!")
		return
	}

	fmt.Printf("Magic: 0x%X\n", stream.Magic)
	fmt.Printf("Version: %d\n", stream.Version)
	fmt.Printf("Contents count: %d\n", len(stream.Contents))
	for i, element := range stream.Contents {
		b, _ := json.MarshalIndent(element, "", "  ")
		fmt.Printf("Element %d: %T - %s\njson: %v\n", i, element, element.String(), string(b))
	}

	fmt.Println("Go test passed!")
}
