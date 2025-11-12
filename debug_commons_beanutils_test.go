package rexjava

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"testing"

	"github.com/esonhugh/go-rex-java/serialization/model"
)

// ExtendedPayloadsData includes all categories
type ExtendedPayloadsData struct {
	None       map[string]PayloadInfo `json:"none"`
	Bash       map[string]PayloadInfo `json:"bash"`
	Cmd        map[string]PayloadInfo `json:"cmd"`
	Powershell map[string]PayloadInfo `json:"powershell"`
}

// TestCommonsBeanutils1DetailedAnalysis 详细分析 CommonsBeanutils1 payload
func TestCommonsBeanutils1DetailedAnalysis(t *testing.T) {
	// 读取 JSON 文件
	data, err := os.ReadFile("ysoserial_payloads.json")
	if err != nil {
		t.Fatalf("Failed to read ysoserial_payloads.json: %v", err)
	}

	var payloads ExtendedPayloadsData
	if err := json.Unmarshal(data, &payloads); err != nil {
		t.Fatalf("Failed to parse JSON: %v", err)
	}

	// 查找 CommonsBeanutils1
	var payloadInfo PayloadInfo
	var found bool
	var payloadName string
	
	// 在所有类别中查找 CommonsBeanutils1
	allMaps := []map[string]PayloadInfo{
		payloads.None,
		payloads.Bash,
		payloads.Cmd,
		payloads.Powershell,
	}
	
	for _, payloadMap := range allMaps {
		if payload, ok := payloadMap["CommonsBeanutils1"]; ok && payload.Bytes != "" {
			payloadInfo = payload
			payloadName = "CommonsBeanutils1"
			found = true
			break
		}
	}
	
	// 如果没找到，找第一个有 bytes 的
	if !found {
		for _, payloadMap := range allMaps {
			for name, payload := range payloadMap {
				if payload.Bytes != "" {
					payloadInfo = payload
					payloadName = name
					found = true
					break
				}
			}
			if found {
				break
			}
		}
	}

	if !found {
		t.Fatal("CommonsBeanutils1 payload not found in JSON")
	}

	// 解码 base64
	bytesData, err := base64.StdEncoding.DecodeString(payloadInfo.Bytes)
	if err != nil {
		t.Fatalf("Failed to decode base64: %v", err)
	}

	fmt.Printf("\n=== %s Payload Analysis ===\n", payloadName)
	fmt.Printf("Payload size: %d bytes\n", len(bytesData))
	fmt.Printf("First 100 bytes (hex): %s\n", hex.EncodeToString(bytesData[:min(100, len(bytesData))]))
	fmt.Printf("\n")

	// 解析字节流
	stream := model.NewStream()
	reader := bytes.NewReader(bytesData)

	fmt.Printf("=== Go Decoder Output ===\n")
	decodeErr := stream.Decode(reader)
	if decodeErr != nil {
		fmt.Printf("❌ Decode ERROR: %v\n", decodeErr)
		fmt.Printf("\nError details:\n")
		fmt.Printf("  Error type: %T\n", decodeErr)
		if errStr, ok := decodeErr.(*model.DecodeError); ok {
			fmt.Printf("  Error message: %s\n", errStr.Message)
		}
	} else {
		fmt.Printf("✅ Decode SUCCESS\n")
	}

	fmt.Printf("\n=== Stream Structure ===\n")
	fmt.Printf("Magic: 0x%04x\n", stream.Magic)
	fmt.Printf("Version: %d\n", stream.Version)
	fmt.Printf("Contents count: %d\n", len(stream.Contents))
	fmt.Printf("References count: %d\n", len(stream.References))

	// 打印前几个 content 的详细信息
	fmt.Printf("\n=== Contents (first 10) ===\n")
	for i, content := range stream.Contents {
		if i >= 10 {
			fmt.Printf("... (showing first 10 of %d)\n", len(stream.Contents))
			break
		}
		fmt.Printf("  [%d] Type: %T\n", i, content)
		fmt.Printf("      String: %s\n", content.String())
		
		// 如果是 NewObject，打印更多信息
		if no, ok := content.(*model.NewObject); ok {
			if no.ClassDesc != nil && no.ClassDesc.Description != nil {
				fmt.Printf("      ClassDesc type: %T\n", no.ClassDesc.Description)
				if ncd, ok := no.ClassDesc.Description.(*model.NewClassDesc); ok {
					if ncd.ClassName != nil {
						fmt.Printf("      ClassName: %s\n", ncd.ClassName.Contents)
					}
					fmt.Printf("      Fields count: %d\n", len(ncd.Fields))
				}
			}
			fmt.Printf("      ClassData count: %d\n", len(no.ClassData))
		}
	}

	// 打印 references
	fmt.Printf("\n=== References (first 20) ===\n")
	for i, ref := range stream.References {
		if i >= 20 {
			fmt.Printf("... (showing first 20 of %d)\n", len(stream.References))
			break
		}
		handle := 0x7e0000 + i
		fmt.Printf("  [%d] Handle: 0x%06x, Type: %T, String: %s\n", i, handle, ref, ref.String())
	}

	// 尝试编码回去
	if decodeErr == nil {
		fmt.Printf("\n=== Encoding Test ===\n")
		encodedData, err := stream.Encode()
		if err != nil {
			fmt.Printf("❌ Encode ERROR: %v\n", err)
		} else {
			fmt.Printf("✅ Encode SUCCESS: %d bytes\n", len(encodedData))
			
			// 比较原始和编码后的数据
			if len(encodedData) != len(bytesData) {
				fmt.Printf("⚠️  Size mismatch: original=%d, encoded=%d\n", len(bytesData), len(encodedData))
			} else {
				// 找出第一个不同的字节
				diffPos := -1
				for i := 0; i < len(bytesData); i++ {
					if bytesData[i] != encodedData[i] {
						diffPos = i
						break
					}
				}
				if diffPos >= 0 {
					fmt.Printf("⚠️  Data mismatch at position %d\n", diffPos)
					fmt.Printf("   Original: 0x%02x\n", bytesData[diffPos])
					fmt.Printf("   Encoded:  0x%02x\n", encodedData[diffPos])
					
					// 打印上下文
					start := max(0, diffPos-10)
					end := min(len(bytesData), diffPos+10)
					fmt.Printf("   Context (original): %s\n", hex.EncodeToString(bytesData[start:end]))
					fmt.Printf("   Context (encoded):  %s\n", hex.EncodeToString(encodedData[start:end]))
				} else {
					fmt.Printf("✅ Data matches perfectly!\n")
				}
			}
		}
	}

	// 找出编码差异的具体位置
	if decodeErr == nil {
		fmt.Printf("\n=== Finding Encoding Differences ===\n")
		encodedData, err := stream.Encode()
		if err == nil {
			findDifferences(bytesData, encodedData)
		}
	}
}

func findDifferences(original, encoded []byte) {
	minLen := min(len(original), len(encoded))
	
	// 找出所有不同的位置
	diffs := []int{}
	for i := 0; i < minLen; i++ {
		if original[i] != encoded[i] {
			diffs = append(diffs, i)
		}
	}
	
	if len(diffs) == 0 && len(original) == len(encoded) {
		fmt.Printf("✅ No differences found! Perfect match.\n")
		return
	}
	
	fmt.Printf("Found %d differences (first 20 shown):\n", len(diffs))
	if len(original) != len(encoded) {
		fmt.Printf("Size difference: original=%d, encoded=%d (diff=%d)\n", 
			len(original), len(encoded), len(encoded)-len(original))
	}
	
	maxDiffs := min(20, len(diffs))
	for i := 0; i < maxDiffs; i++ {
		pos := diffs[i]
		fmt.Printf("\n  Position %d (0x%04x):\n", pos, pos)
		fmt.Printf("    Original: 0x%02x", original[pos])
		if pos < len(original)-1 {
			fmt.Printf(" 0x%02x", original[pos+1])
		}
		fmt.Printf("\n")
		fmt.Printf("    Encoded:  0x%02x", encoded[pos])
		if pos < len(encoded)-1 {
			fmt.Printf(" 0x%02x", encoded[pos+1])
		}
		fmt.Printf("\n")
		
		// 显示上下文（前后各 10 字节）
		start := max(0, pos-10)
		endOrig := min(len(original), pos+10)
		endEnc := min(len(encoded), pos+10)
		
		fmt.Printf("    Context (original): %s\n", hex.EncodeToString(original[start:endOrig]))
		fmt.Printf("    Context (encoded):  %s\n", hex.EncodeToString(encoded[start:endEnc]))
		
		// 尝试识别这是什么类型的数据
		if pos >= 4 {
			// 检查是否是 opcode
			opcode := original[start]
			switch opcode {
			case 0x73: // TC_OBJECT
				fmt.Printf("    Context type: TC_OBJECT area\n")
			case 0x72: // TC_CLASSDESC
				fmt.Printf("    Context type: TC_CLASSDESC area\n")
			case 0x74: // TC_STRING
				fmt.Printf("    Context type: TC_STRING area\n")
			case 0x71: // TC_REFERENCE
				fmt.Printf("    Context type: TC_REFERENCE area\n")
			}
		}
	}
	
	if len(diffs) > maxDiffs {
		fmt.Printf("\n... and %d more differences\n", len(diffs)-maxDiffs)
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

