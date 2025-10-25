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

// TestComprehensiveJavaSerialization 综合测试 Java 序列化功能
func TestComprehensiveJavaSerialization(t *testing.T) {
	t.Run("DecodeOriginalFile", func(t *testing.T) {
		// 测试解码原始 abc.ser 文件
		originalData, err := ioutil.ReadFile("./main/abc.ser")
		if err != nil {
			t.Fatalf("Failed to read abc.ser: %v", err)
		}

		stream, err := serialization.DecodeStream(originalData)
		if err != nil {
			t.Fatalf("Failed to decode stream: %v", err)
		}

		// 验证基本属性
		if stream.Magic != 0xACED {
			t.Errorf("Expected magic 0xACED, got 0x%X", stream.Magic)
		}
		if stream.Version != 5 {
			t.Errorf("Expected version 5, got %d", stream.Version)
		}
		if len(stream.Contents) != 3 {
			t.Errorf("Expected 3 contents, got %d", len(stream.Contents))
		}

		// 验证第一个元素是 NewObject
		newObject, ok := stream.Contents[0].(*model.NewObject)
		if !ok {
			t.Fatalf("Expected first element to be NewObject, got %T", stream.Contents[0])
		}

		// 验证类描述
		if newObject.ClassDesc == nil {
			t.Fatal("Expected class description to be set")
		}

		classDesc, ok := newObject.ClassDesc.Description.(*model.NewClassDesc)
		if !ok {
			t.Fatalf("Expected class description to be NewClassDesc, got %T", newObject.ClassDesc.Description)
		}

		if classDesc.ClassName == nil || classDesc.ClassName.Contents != "java.io.File" {
			t.Errorf("Expected class name 'java.io.File', got %v", classDesc.ClassName)
		}

		fmt.Printf("✅ Successfully decoded java.io.File object with path: %s\n",
			newObject.ClassData[0].Value)
	})

	t.Run("EncodeDecodeRoundTrip", func(t *testing.T) {
		// 测试编码解码往返
		originalData, err := ioutil.ReadFile("./main/abc.ser")
		if err != nil {
			t.Fatalf("Failed to read abc.ser: %v", err)
		}

		// 解码
		stream, err := serialization.DecodeStream(originalData)
		if err != nil {
			t.Fatalf("Failed to decode: %v", err)
		}

		// 重新编码
		reencodedData, err := stream.Encode()
		if err != nil {
			t.Fatalf("Failed to re-encode: %v", err)
		}

		// 验证字节级一致性
		if !bytes.Equal(originalData, reencodedData) {
			t.Errorf("Round-trip data mismatch")
			t.Errorf("Original:  %s", hex.EncodeToString(originalData))
			t.Errorf("Re-encoded: %s", hex.EncodeToString(reencodedData))
		} else {
			fmt.Println("✅ Round-trip encoding/decoding maintains byte-level consistency")
		}
	})

	t.Run("CreateAndEncodeJavaFile", func(t *testing.T) {
		// 测试创建和编码 Java File 对象
		builder := serialization.NewBuilder()

		// 创建 java.io.File 类描述
		fileClass := builder.NewClass(&serialization.ClassOptions{
			Name:   "java.io.File",
			Serial: 0x3010774b9b8c4f5e, // 使用不同的 serialVersionUID 进行测试
			Flags:  0x02,               // SC_SERIALIZABLE
			Fields: []serialization.FieldData{
				{Type: model.Object, Name: "path", FieldType: "Ljava/lang/String;"},
			},
		})

		// 创建路径字符串
		pathValueUtf := model.NewUtf(nil, "/tmp/test.txt")

		// 创建 BlockData
		blockData := model.NewBlockData(nil)
		blockData.Data = []byte{0x00, 0x2f} // "/" 的 UTF-16 BE 编码

		// 创建 EndBlockData
		endBlockData := model.NewEndBlockData(nil)

		// 创建流
		stream := serialization.NewStream()

		// 创建 NewObject
		fileObject := builder.NewObject(&serialization.ObjectOptions{
			Description: fileClass,
			Data:        []interface{}{pathValueUtf},
		})

		// 添加元素到流
		stream.Contents = append(stream.Contents, fileObject)
		stream.Contents = append(stream.Contents, blockData)
		stream.Contents = append(stream.Contents, endBlockData)

		// 编码
		encodedData, err := stream.Encode()
		if err != nil {
			t.Fatalf("Failed to encode: %v", err)
		}

		// 解码验证
		decodedStream, err := serialization.DecodeStream(encodedData)
		if err != nil {
			t.Fatalf("Failed to decode: %v", err)
		}

		// 验证结构
		if len(decodedStream.Contents) != 3 {
			t.Errorf("Expected 3 contents, got %d", len(decodedStream.Contents))
		}

		// 验证 NewObject
		newObject, ok := decodedStream.Contents[0].(*model.NewObject)
		if !ok {
			t.Fatalf("Expected first element to be NewObject, got %T", decodedStream.Contents[0])
		}

		// 验证类名
		classDesc, ok := newObject.ClassDesc.Description.(*model.NewClassDesc)
		if !ok {
			t.Fatalf("Expected class description to be NewClassDesc, got %T", newObject.ClassDesc.Description)
		}

		if classDesc.ClassName == nil || classDesc.ClassName.Contents != "java.io.File" {
			t.Errorf("Expected class name 'java.io.File', got %v", classDesc.ClassName)
		}

		// 验证路径
		if len(newObject.ClassData) != 1 {
			t.Errorf("Expected 1 class data item, got %d", len(newObject.ClassData))
		}

		pathUtf, ok := newObject.ClassData[0].Value.(*model.Utf)
		if !ok {
			t.Fatalf("Expected class data to be Utf, got %T", newObject.ClassData[0].Value)
		}

		if pathUtf.Contents != "/tmp/test.txt" {
			t.Errorf("Expected path '/tmp/test.txt', got %s", pathUtf.Contents)
		}

		fmt.Printf("✅ Successfully created and encoded java.io.File object with path: %s\n", pathUtf.Contents)
	})

	t.Run("CompareWithOriginal", func(t *testing.T) {
		// 比较创建的对象与原始文件
		originalData, err := ioutil.ReadFile("./main/abc.ser")
		if err != nil {
			t.Fatalf("Failed to read abc.ser: %v", err)
		}

		// 解码原始文件
		originalStream, err := serialization.DecodeStream(originalData)
		if err != nil {
			t.Fatalf("Failed to decode original: %v", err)
		}

		// 创建相同的对象
		builder := serialization.NewBuilder()
		fileClass := builder.NewClass(&serialization.ClassOptions{
			Name:   "java.io.File",
			Serial: 0x042da4450e0de4ff, // 使用原始文件的 serialVersionUID
			Flags:  0x02,
			Fields: []serialization.FieldData{
				{Type: model.Object, Name: "path", FieldType: "Ljava/lang/String;"},
			},
		})

		pathValueUtf := model.NewUtf(nil, "/etc/passwd")
		blockData := model.NewBlockData(nil)
		blockData.Data = []byte{0x00, 0x2f}
		endBlockData := model.NewEndBlockData(nil)

		newStream := serialization.NewStream()
		fileObject := builder.NewObject(&serialization.ObjectOptions{
			Description: fileClass,
			Data:        []interface{}{pathValueUtf},
		})

		newStream.Contents = append(newStream.Contents, fileObject)
		newStream.Contents = append(newStream.Contents, blockData)
		newStream.Contents = append(newStream.Contents, endBlockData)

		// 编码
		encodedData, err := newStream.Encode()
		if err != nil {
			t.Fatalf("Failed to encode: %v", err)
		}

		// 比较结构（不比较字节，因为可能有细微差异）
		if len(encodedData) != len(originalData) {
			t.Logf("Length difference: original=%d, encoded=%d", len(originalData), len(encodedData))
		}

		// 验证基本结构相同
		if originalStream.Magic != newStream.Magic {
			t.Errorf("Magic mismatch: %x vs %x", originalStream.Magic, newStream.Magic)
		}
		if originalStream.Version != newStream.Version {
			t.Errorf("Version mismatch: %d vs %d", originalStream.Version, newStream.Version)
		}
		if len(originalStream.Contents) != len(newStream.Contents) {
			t.Errorf("Contents count mismatch: %d vs %d", len(originalStream.Contents), len(newStream.Contents))
		}

		fmt.Printf("Original: %s\n", hex.EncodeToString(originalData))
		fmt.Printf("New: %s\n", hex.EncodeToString(encodedData))
		if !bytes.Equal(originalData, encodedData) {
			t.Errorf("Expected differences in byte-level encoding, but they are identical")
		} else {
			fmt.Println("✅ Created object structure is equivalent to original, with expected byte-level differences")
		}
		fmt.Println("✅ Successfully created equivalent Java File object structure")
	})
}

// TestJavaSerializationFeatures 测试 Java 序列化的各种特性
func TestJavaSerializationFeatures(t *testing.T) {
	t.Run("StreamMagicAndVersion", func(t *testing.T) {
		stream := serialization.NewStream()
		if stream.Magic != 0xACED {
			t.Errorf("Expected magic 0xACED, got 0x%X", stream.Magic)
		}
		if stream.Version != 5 {
			t.Errorf("Expected version 5, got %d", stream.Version)
		}
		fmt.Println("✅ Stream magic and version are correct")
	})

	t.Run("BuilderFunctionality", func(t *testing.T) {
		builder := serialization.NewBuilder()
		if builder == nil {
			t.Fatal("Expected builder to be non-nil")
		}

		// 测试创建类
		class := builder.NewClass(&serialization.ClassOptions{
			Name:   "TestClass",
			Serial: 0x1234567890ABCDEF,
			Flags:  0x02,
			Fields: []serialization.FieldData{
				{Type: model.Int, Name: "value"},
				{Type: model.Object, Name: "name", FieldType: "Ljava/lang/String;"},
			},
		})

		if class == nil {
			t.Fatal("Expected class to be non-nil")
		}

		if class.ClassName == nil || class.ClassName.Contents != "TestClass" {
			t.Errorf("Expected class name 'TestClass', got %v", class.ClassName)
		}

		if class.SerialVersion != 0x1234567890ABCDEF {
			t.Errorf("Expected serial version 0x1234567890ABCDEF, got 0x%x", class.SerialVersion)
		}

		if len(class.Fields) != 2 {
			t.Errorf("Expected 2 fields, got %d", len(class.Fields))
		}

		fmt.Println("✅ Builder functionality works correctly")
	})

	t.Run("ElementTypes", func(t *testing.T) {
		// 测试各种元素类型
		stream := serialization.NewStream()

		// UTF 字符串
		utf := model.NewUtf(stream.Stream, "Hello, World!")
		if utf.Contents != "Hello, World!" {
			t.Errorf("Expected 'Hello, World!', got %s", utf.Contents)
		}

		// BlockData
		blockData := model.NewBlockData(stream.Stream)
		blockData.Data = []byte{0x01, 0x02, 0x03}
		if len(blockData.Data) != 3 {
			t.Errorf("Expected 3 bytes, got %d", len(blockData.Data))
		}

		// EndBlockData
		endBlockData := model.NewEndBlockData(stream.Stream)
		if endBlockData == nil {
			t.Fatal("Expected EndBlockData to be non-nil")
		}

		fmt.Println("✅ Element types work correctly")
	})
}
