# RexJava

RexJava 是一个用 Go 语言编写的 Java 序列化流解析库，从 Ruby 的 rex-java 库移植而来。该库专门用于安全研究和渗透测试，能够解析和构建 Java 对象序列化格式的二进制流。

## 功能特性

- **完整的 Java 序列化协议支持**：实现了 Java 序列化协议的完整规范
- **类型安全**：严格的类型检查和验证机制
- **错误处理**：自定义的 DecodeError 和 EncodeError 异常类
- **引用管理**：支持对象引用和循环引用处理
- **可扩展性**：模块化设计便于添加新的序列化类型支持
- **构建器模式**：提供高级 API 用于构建序列化对象

## 安装

```bash
go get rexjava
```

## 快速开始

### 创建 Java 序列化流

```go
package main

import (
    "fmt"
    "rexjava"
)

func main() {
    // 创建构建器
    builder := rexjava.NewBuilder()
    
    // 创建类描述符
    classOpts := &rexjava.ClassOptions{
        Name:     "java.lang.String",
        Serial:   0x1234567890ABCDEF,
        Flags:    0x02, // SC_SERIALIZABLE
        Fields: []rexjava.FieldData{
            {Type: "int", Name: "value"},
            {Type: "object", Name: "next", FieldType: "java.lang.String"},
        },
    }
    
    classDesc := builder.NewClass(classOpts)
    
    // 创建对象
    objectOpts := &rexjava.ObjectOptions{
        Description: classDesc,
        Data: []interface{}{
            []interface{}{"int", 42},
            []interface{}{"object", "hello"},
        },
    }
    
    object := builder.NewObject(objectOpts)
    
    // 创建流
    stream := rexjava.NewStream()
    stream.Contents = []rexjava.Element{object}
    
    // 编码
    encoded, err := stream.Encode()
    if err != nil {
        panic(err)
    }
    
    fmt.Printf("Encoded data: %x\n", encoded)
}
```

### 解析 Java 序列化流

```go
package main

import (
    "bytes"
    "fmt"
    "rexjava"
)

func main() {
    // 假设你有一个 Java 序列化的字节数组
    data := []byte{0xac, 0xed, 0x00, 0x05, 0x73, 0x00, 0x11, 0x6a, 0x61, 0x76, 0x61, 0x2e, 0x6c, 0x61, 0x6e, 0x67, 0x2e, 0x53, 0x74, 0x72, 0x69, 0x6e, 0x67}
    
    // 创建流
    stream := rexjava.NewStream()
    
    // 解码
    reader := bytes.NewReader(data)
    err := stream.Decode(reader)
    if err != nil {
        panic(err)
    }
    
    // 打印流内容
    fmt.Println(stream.String())
}
```

## API 文档

### 核心类型

#### Stream
表示 Java 序列化流的主要容器。

```go
type Stream struct {
    Magic      uint16
    Version    uint16
    Contents   []Element
    References []Element
}
```

#### Element
所有序列化元素的基接口。

```go
type Element interface {
    Decode(reader io.Reader, stream *Stream) error
    Encode() ([]byte, error)
    String() string
}
```

#### Builder
提供高级 API 用于构建序列化对象。

```go
type Builder struct{}

func NewBuilder() *Builder
func (b *Builder) NewClass(opts *ClassOptions) *NewClassDesc
func (b *Builder) NewObject(opts *ObjectOptions) *NewObject
func (b *Builder) NewArray(opts *ArrayOptions) *NewArray
```

### 支持的元素类型

- **Utf**: UTF-8 字符串
- **NewObject**: Java 对象
- **NewArray**: Java 数组
- **ClassDesc**: 类描述符
- **Field**: 字段描述符
- **Reference**: 对象引用
- **NullReference**: 空引用
- **BlockData**: 块数据
- **EndBlockData**: 块数据结束标记
- **Reset**: 重置标记

### 错误处理

库提供了两种自定义错误类型：

```go
type DecodeError struct {
    Message string
}

type EncodeError struct {
    Message string
}
```

## 使用场景

1. **安全研究**：分析恶意 Java 序列化数据
2. **渗透测试**：生成用于测试的 Java 序列化载荷
3. **逆向工程**：理解 Java 应用程序的序列化行为
4. **工具开发**：为其他安全工具提供 Java 序列化处理能力

## 测试

运行测试：

```bash
go test ./...
```

运行测试并查看覆盖率：

```bash
go test -cover ./...
```

## 贡献

欢迎提交 Issue 和 Pull Request！

## 许可证

本项目采用与原始 Ruby 库相同的许可证。

## 致谢

本项目基于 [rex-java](https://github.com/rapid7/rex-java) Ruby 库，感谢 Metasploit 团队和 Juan Vasquez 的原始工作。
