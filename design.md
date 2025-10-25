# RexJava 设计文档

## 项目概述

RexJava 是一个用 Go 语言编写的 Java 序列化流解析库，从 Ruby 的 rex-java 库移植而来。该库专门用于安全研究和渗透测试，能够解析和构建 Java 对象序列化格式的二进制流。

## 设计原则

### 1. 模块化设计
- 将功能分解为独立的模块，每个模块负责特定的功能
- 使用 Go 的包系统来组织代码结构
- 保持模块间的低耦合和高内聚

### 2. 接口驱动
- 定义清晰的接口来抽象不同的序列化元素
- 使用 Go 的接口特性来实现多态
- 便于扩展和测试

### 3. 错误处理
- 使用自定义错误类型来提供详细的错误信息
- 遵循 Go 的错误处理最佳实践
- 提供有意义的错误消息

### 4. 类型安全
- 利用 Go 的强类型系统
- 避免运行时类型错误
- 提供编译时类型检查

## 架构设计

### 包结构

```
rexjava/
├── rexjava.go              # 主包入口
├── serialization/          # 序列化核心包
│   ├── constants.go        # 常量定义
│   ├── errors.go          # 错误类型定义
│   ├── builder.go         # 构建器模式实现
│   ├── serialization.go   # 序列化流实现
│   └── model/             # 数据模型包
│       ├── element.go     # 基础元素接口和实现
│       ├── stream.go      # 流模型
│       ├── utf.go         # UTF字符串模型
│       ├── field.go       # 字段模型
│       ├── class_desc.go  # 类描述符模型
│       ├── new_object.go  # 对象模型
│       └── ...            # 其他模型
```

### 核心组件

#### 1. Element 接口
所有序列化元素的基接口，定义了基本的序列化/反序列化方法：

```go
type Element interface {
    Decode(reader io.Reader, stream *Stream) error
    Encode() ([]byte, error)
    String() string
}
```

#### 2. Stream 结构
Java 序列化流的主要容器：

```go
type Stream struct {
    *BaseElement
    Magic      uint16
    Version    uint16
    Contents   []Element
    References []Element
}
```

#### 3. Builder 模式
提供高级 API 用于构建序列化对象：

```go
type Builder struct{}

func (b *Builder) NewClass(opts *ClassOptions) *NewClassDesc
func (b *Builder) NewObject(opts *ObjectOptions) *NewObject
func (b *Builder) NewArray(opts *ArrayOptions) *NewArray
```

## 数据模型设计

### 1. 基础元素
- **BaseElement**: 提供所有元素的通用功能
- **Element**: 定义元素的基本接口

### 2. 具体元素类型
- **Utf**: UTF-8 字符串表示
- **NewObject**: Java 对象表示
- **NewArray**: Java 数组表示
- **ClassDesc**: 类描述符
- **Field**: 字段描述符
- **Reference**: 对象引用
- **NullReference**: 空引用

### 3. 辅助类型
- **BlockData**: 块数据
- **EndBlockData**: 块数据结束标记
- **Reset**: 重置标记

## 序列化协议支持

### 1. 常量定义
定义了 Java 序列化协议的所有常量：

```go
const (
    StreamMagic = 0xaced
    StreamVersion = 5
    TC_NULL = 0x70
    TC_REFERENCE = 0x71
    // ... 其他常量
)
```

### 2. 类型代码映射
提供了类型代码到类型名称的映射：

```go
var TypeCodes = map[byte]string{
    'B': "byte",
    'C': "char",
    'D': "double",
    // ... 其他类型
}
```

### 3. 序列化标志
定义了序列化标志：

```go
const (
    SC_SERIALIZABLE = 0x02
    SC_EXTERNALIZABLE = 0x04
    SC_ENUM = 0x10
)
```

## 错误处理设计

### 1. 自定义错误类型
定义了两种主要的错误类型：

```go
type DecodeError struct {
    Message string
}

type EncodeError struct {
    Message string
}
```

### 2. 错误处理策略
- 在解码过程中遇到错误时返回 DecodeError
- 在编码过程中遇到错误时返回 EncodeError
- 提供详细的错误消息以便调试

## 构建器模式设计

### 1. 选项结构
为不同的构建操作定义了选项结构：

```go
type ClassOptions struct {
    Name        string
    Serial      uint64
    Flags       uint8
    Fields      []FieldData
    Annotations []Element
    SuperClass  Element
}

type ObjectOptions struct {
    Description *NewClassDesc
    ClassOpts   *ClassOptions
    Data        []interface{}
}

type ArrayOptions struct {
    Description *NewClassDesc
    ClassOpts   *ClassOptions
    ValuesType  string
    Values      []interface{}
}
```

### 2. 构建流程
1. 创建 Builder 实例
2. 使用选项结构配置要构建的对象
3. 调用相应的构建方法
4. 返回构建好的对象

## 测试设计

### 1. 测试覆盖
- 为每个包编写单元测试
- 确保测试覆盖率超过 80%
- 测试各种边界条件和错误情况

### 2. 测试结构
- 使用 Go 的 testing 包
- 采用表驱动测试方法
- 为每个功能编写独立的测试函数

### 3. 测试数据
- 使用真实的 Java 序列化数据作为测试用例
- 创建各种类型的测试数据
- 验证编码和解码的一致性

## 性能考虑

### 1. 内存管理
- 使用 Go 的垃圾回收器
- 避免不必要的内存分配
- 重用对象以减少 GC 压力

### 2. 并发安全
- 设计为不可变对象
- 避免共享可变状态
- 使用值传递而非引用传递

### 3. 性能优化
- 使用字节切片而非字符串进行二进制操作
- 预分配切片容量
- 避免不必要的类型转换

## 扩展性设计

### 1. 接口扩展
- 通过实现 Element 接口来添加新的元素类型
- 保持接口的向后兼容性
- 使用组合而非继承

### 2. 功能扩展
- 通过添加新的构建器方法来扩展功能
- 保持 API 的一致性
- 使用选项模式来配置新功能

### 3. 协议扩展
- 通过添加新的常量来支持新的协议特性
- 保持现有代码的兼容性
- 使用版本控制来管理协议变更

## 安全考虑

### 1. 输入验证
- 验证所有输入数据
- 防止缓冲区溢出
- 检查数据长度和格式

### 2. 错误处理
- 不暴露内部实现细节
- 提供安全的错误消息
- 避免信息泄露

### 3. 资源管理
- 限制内存使用
- 防止无限递归
- 设置合理的超时时间

## 未来改进

### 1. 功能增强
- 支持更多的 Java 序列化特性
- 添加流式处理支持
- 提供更高级的 API

### 2. 性能优化
- 使用更高效的数据结构
- 实现并行处理
- 优化内存使用

### 3. 工具支持
- 添加命令行工具
- 提供图形界面
- 集成到其他安全工具中

## 总结

RexJava 的设计遵循了 Go 语言的最佳实践，采用了模块化、接口驱动的架构，提供了完整的 Java 序列化协议支持。通过构建器模式和选项结构，提供了易用的 API。错误处理和测试设计确保了代码的可靠性和可维护性。该库为安全研究和渗透测试提供了强大的 Java 序列化处理能力。
