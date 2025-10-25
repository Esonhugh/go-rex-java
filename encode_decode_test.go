package rexjava

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"testing"

	"github.com/esonhugh/go-rex-java/serialization"
	"github.com/esonhugh/go-rex-java/serialization/model"
)

// TestEncodeDecodeJavaFile 测试 Java File 对象的编码和解码
func TestEncodeDecodeJavaFile(t *testing.T) {
	// 读取原始的 abc.ser 文件
	originalData, err := ioutil.ReadFile("./main/abc.ser")
	if err != nil {
		t.Fatalf("Failed to read abc.ser: %v", err)
	}

	fmt.Printf("Original file size: %d bytes\n", len(originalData))
	fmt.Printf("Original file hex: %s\n", hex.EncodeToString(originalData))

	// 解码原始文件
	originalStream, err := serialization.DecodeStream(originalData)
	if err != nil {
		t.Fatalf("Failed to decode original stream: %v", err)
	}

	fmt.Printf("Original stream magic: 0x%X\n", originalStream.Magic)
	fmt.Printf("Original stream version: %d\n", originalStream.Version)
	fmt.Printf("Original stream contents count: %d\n", len(originalStream.Contents))

	// 打印原始内容详情
	for i, element := range originalStream.Contents {
		fmt.Printf("Original element %d: %T - %s\n", i, element, element.String())
	}

	// 使用 Builder 创建相同的对象
	builder := serialization.NewBuilder()

	// 创建 java.io.File 类描述
	fileClass := builder.NewClass(&serialization.ClassOptions{
		Name:   "java.io.File",
		Serial: 0x3010774b9b8c4f5e, // java.io.File 的 serialVersionUID
		Flags:  0x02,               // SC_SERIALIZABLE
		Fields: []serialization.FieldData{
			{Type: model.Object, Name: "path", FieldType: "Ljava/lang/String;"},
		},
	})

	// 创建字符串 "/etc/passwd" 的 UTF 表示
	pathValueUtf := model.NewUtf(nil, "/etc/passwd")

	// 创建 BlockData 包含路径数据
	blockData := model.NewBlockData(nil)
	blockData.Data = []byte{0x00, 0x2f} // "/" 的 UTF-16 BE 编码

	// 创建 EndBlockData
	endBlockData := model.NewEndBlockData(nil)

	// 创建新的流
	newStream := serialization.NewStream()

	// 创建 NewObject (包含类描述)
	fileObject := builder.NewObject(&serialization.ObjectOptions{
		Description: fileClass,
		Data:        []interface{}{pathValueUtf},
	})

	// 添加对象到流中
	newStream.Contents = append(newStream.Contents, fileObject)

	// 添加 BlockData 和 EndBlockData
	newStream.Contents = append(newStream.Contents, blockData)
	newStream.Contents = append(newStream.Contents, endBlockData)

	// 编码新流
	encodedData, err := newStream.Encode()
	if err != nil {
		t.Fatalf("Failed to encode new stream: %v", err)
	}

	fmt.Printf("Encoded data size: %d bytes\n", len(encodedData))
	fmt.Printf("Encoded data hex: %s\n", hex.EncodeToString(encodedData))

	// 解码编码后的数据
	decodedStream, err := serialization.DecodeStream(encodedData)
	if err != nil {
		t.Fatalf("Failed to decode encoded stream: %v", err)
	}

	fmt.Printf("Decoded stream magic: 0x%X\n", decodedStream.Magic)
	fmt.Printf("Decoded stream version: %d\n", decodedStream.Version)
	fmt.Printf("Decoded stream contents count: %d\n", len(decodedStream.Contents))

	// 打印解码后的内容详情
	for i, element := range decodedStream.Contents {
		fmt.Printf("Decoded element %d: %T - %s\n", i, element, element.String())
	}

	// 验证基本属性
	if decodedStream.Magic != originalStream.Magic {
		t.Errorf("Magic mismatch: expected 0x%X, got 0x%X", originalStream.Magic, decodedStream.Magic)
	}

	if decodedStream.Version != originalStream.Version {
		t.Errorf("Version mismatch: expected %d, got %d", originalStream.Version, decodedStream.Version)
	}

	// 验证内容数量
	if len(decodedStream.Contents) != len(originalStream.Contents) {
		t.Errorf("Contents count mismatch: expected %d, got %d", len(originalStream.Contents), len(decodedStream.Contents))
	}

	// 验证每个元素类型
	for i, originalElement := range originalStream.Contents {
		if i >= len(decodedStream.Contents) {
			t.Errorf("Missing element at index %d", i)
			continue
		}

		decodedElement := decodedStream.Contents[i]
		originalType := fmt.Sprintf("%T", originalElement)
		decodedType := fmt.Sprintf("%T", decodedElement)

		if originalType != decodedType {
			t.Errorf("Element %d type mismatch: expected %s, got %s", i, originalType, decodedType)
		}
	}

	fmt.Println("✅ Encode/Decode test passed!")
}

// TestRoundTripConsistency 测试往返一致性
func TestRoundTripConsistency(t *testing.T) {
	// 读取原始文件
	originalData, err := ioutil.ReadFile("./main/abc.ser")
	if err != nil {
		t.Fatalf("Failed to read abc.ser: %v", err)
	}

	// 解码原始文件
	originalStream, err := serialization.DecodeStream(originalData)
	if err != nil {
		t.Fatalf("Failed to decode original stream: %v", err)
	}

	// 重新编码
	reencodedData, err := originalStream.Encode()
	if err != nil {
		t.Fatalf("Failed to re-encode stream: %v", err)
	}

	// 比较字节数据
	if !bytes.Equal(originalData, reencodedData) {
		t.Errorf("Round-trip data mismatch")
		t.Errorf("Original length: %d, Re-encoded length: %d", len(originalData), len(reencodedData))

		// 显示差异
		minLen := len(originalData)
		if len(reencodedData) < minLen {
			minLen = len(reencodedData)
		}

		for i := 0; i < minLen; i++ {
			if originalData[i] != reencodedData[i] {
				t.Errorf("Byte difference at position %d: original=0x%02x, re-encoded=0x%02x",
					i, originalData[i], reencodedData[i])
			}
		}
	} else {
		fmt.Println("✅ Round-trip consistency test passed!")
	}
}

// TestStreamStructure 测试流结构
func TestStreamStructure(t *testing.T) {
	// 读取原始文件
	originalData, err := ioutil.ReadFile("./main/abc.ser")
	if err != nil {
		t.Fatalf("Failed to read abc.ser: %v", err)
	}

	// 解码原始文件
	stream, err := serialization.DecodeStream(originalData)
	if err != nil {
		t.Fatalf("Failed to decode stream: %v", err)
	}

	// 验证流结构
	if stream.Magic != 0xACED {
		t.Errorf("Invalid magic number: expected 0xACED, got 0x%X", stream.Magic)
	}

	if stream.Version != 5 {
		t.Errorf("Invalid version: expected 5, got %d", stream.Version)
	}

	// 验证内容结构
	if len(stream.Contents) < 3 {
		t.Errorf("Expected at least 3 contents, got %d", len(stream.Contents))
	}

	// 验证第一个元素是 NewObject
	if _, ok := stream.Contents[0].(*model.NewObject); !ok {
		t.Errorf("Expected first element to be NewObject, got %T", stream.Contents[0])
	}

	// 验证第二个元素是 BlockData
	if _, ok := stream.Contents[1].(*model.BlockData); !ok {
		t.Errorf("Expected second element to be BlockData, got %T", stream.Contents[1])
	}

	// 验证第三个元素是 EndBlockData
	if _, ok := stream.Contents[2].(*model.EndBlockData); !ok {
		t.Errorf("Expected third element to be EndBlockData, got %T", stream.Contents[2])
	}

	fmt.Println("✅ Stream structure test passed!")
}
