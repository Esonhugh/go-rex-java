package rexjava

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"reflect"
	"testing"

	"github.com/esonhugh/go-rex-java/serialization/model"
)

// TestAdditionalPayloadsDebug打印多个常见 payload 的分析信息。
// 仅用于调试，默认不失败（即使编码仍然不一致）。
func TestAdditionalPayloadsDebug(t *testing.T) {
	payloads := loadExtendedPayloads(t)
	names := []string{
		"Groovy1",
		"Hibernate1",
		"JSON1",
		"Vaadin1",
		"BeanShell1",
		"JBossInterceptors1",
		"JavassistWeld1",
		"MozillaRhino1",
		"MozillaRhino2",
	}

	for _, name := range names {
		info, category, ok := findPayload(payloads, name)
		if !ok {
			t.Logf("payload %s not found; category=%s", name, category)
			continue
		}

		t.Run(name, func(t *testing.T) {
			analyzePayloadBytes(t, name, info)
		})
	}
}

// analyzePayloadBytes decodes -> encodes并打印差异，用于调试。
func analyzePayloadBytes(t *testing.T, name string, info PayloadInfo) {
	bytesData, err := base64.StdEncoding.DecodeString(info.Bytes)
	if err != nil {
		t.Logf("%s: failed to decode base64: %v", name, err)
		return
	}

	stream := model.NewStream()
	if err := stream.Decode(bytes.NewReader(bytesData)); err != nil {
		t.Logf("%s: decode failed: %v", name, err)
		return
	}

	t.Logf("%s: contents count=%d", name, len(stream.Contents))

	// 打印部分引用信息（有限内容）
	if len(stream.References) > 0 {
		limit := 10
		if len(stream.References) < limit {
			limit = len(stream.References)
		}
		t.Logf("%s: references count=%d (first %d shown)", name, len(stream.References), limit)
		for i := 0; i < limit; i++ {
			if utf, ok := stream.References[i].(*model.Utf); ok {
				t.Logf("  ref[%d] Utf=%q ptr=%p", i, utf.Contents, utf)
			}
		}
	}

	if name == "Groovy1" {
		for ci, content := range stream.Contents {
			if obj, ok := content.(*model.NewObject); ok && obj.ClassDesc != nil {
				if desc, ok := obj.ClassDesc.Description.(*model.NewClassDesc); ok {
					for fi, field := range desc.Fields {
						if field.FieldType != nil {
							utf := field.FieldType
							refIdx := -1
							for ri, ref := range stream.References {
								if ref == utf {
									refIdx = ri
									break
								}
								if refUtf, ok := ref.(*model.Utf); ok && refUtf.Contents == utf.Contents {
									refIdx = ri
									break
								}
							}
							t.Logf("  content[%d] field[%d] name=%q type=%q ptr=%p refIdx=%d", ci, fi, field.Name.Contents, utf.Contents, utf, refIdx)
						}
					}
				}
			}
		}

		for ri, ref := range stream.References {
			if desc, ok := ref.(*model.NewClassDesc); ok {
				if desc.ClassName != nil {
					t.Logf("  ref[%d] class=%q fields=%d", ri, desc.ClassName.Contents, len(desc.Fields))
				}
				for fi, field := range desc.Fields {
					if field.FieldType != nil {
						utf := field.FieldType
						refIdx := -1
						for sIdx, sRef := range stream.References {
							if sRef == utf {
								refIdx = sIdx
								break
							}
							if sUtf, ok := sRef.(*model.Utf); ok && sUtf.Contents == utf.Contents {
								refIdx = sIdx
								break
							}
						}
						t.Logf("    ref[%d] field[%d] name=%q type=%q ptr=%p refIdx=%d", ri, fi, field.Name.Contents, utf.Contents, utf, refIdx)
					}
				}
			}
		}
	}

	encodedData, err := stream.Encode()
	if err != nil {
		t.Logf("%s: encode failed: %v", name, err)
		return
	}

	if bytes.Equal(bytesData, encodedData) {
		t.Logf("%s: ✅ exact match (%d bytes)", name, len(bytesData))
		return
	}

	// 找出第一处差异
	firstDiff := -1
	minLen := len(bytesData)
	if len(encodedData) < minLen {
		minLen = len(encodedData)
	}
	for i := 0; i < minLen; i++ {
		if bytesData[i] != encodedData[i] {
			firstDiff = i
			break
		}
	}

	if firstDiff >= 0 {
		start := firstDiff - 10
		if start < 0 {
			start = 0
		}
		end := firstDiff + 10
		if end > len(bytesData) {
			end = len(bytesData)
		}
		if end > len(encodedData) {
			end = len(encodedData)
		}

		t.Logf("%s: ⚠️ first diff at %d (0x%04x): original=0x%02x, encoded=0x%02x", name, firstDiff, firstDiff, bytesData[firstDiff], encodedData[firstDiff])
		t.Logf("%s: context original: %s", name, hex.EncodeToString(bytesData[start:end]))
		t.Logf("%s: context encoded:  %s", name, hex.EncodeToString(encodedData[start:end]))
	}

	// 打印总体差异数量（限制20个，复用 findDifferences 以 fmt 输出）
	findDifferences(bytesData, encodedData)

	if name == "JSON1" && !bytes.Equal(bytesData, encodedData) {
		describeStructureDiff(t, bytesData, encodedData)
	}
}

func describeStructureDiff(t *testing.T, original, encoded []byte) {
	origStream := model.NewStream()
	if err := origStream.Decode(bytes.NewReader(original)); err != nil {
		t.Logf("JSON1: failed to decode original stream for structure diff: %v", err)
		return
	}

	encStream := model.NewStream()
	if err := encStream.Decode(bytes.NewReader(encoded)); err != nil {
		t.Logf("JSON1: failed to decode encoded stream for structure diff: %v", err)
		return
	}

	minLen := len(origStream.Contents)
	if len(encStream.Contents) < minLen {
		minLen = len(encStream.Contents)
	}

	for i := 0; i < minLen && i < 12; i++ {
		origElem := origStream.Contents[i]
		encElem := encStream.Contents[i]
		t.Logf("JSON1: content[%d] original=%T -> %s", i, origElem, origElem.String())
		t.Logf("JSON1: content[%d] encoded =%T -> %s", i, encElem, encElem.String())
	}

	for i := 0; i < minLen; i++ {
		origElem := origStream.Contents[i]
		encElem := encStream.Contents[i]
		if reflect.TypeOf(origElem) != reflect.TypeOf(encElem) || origElem.String() != encElem.String() {
			t.Logf("JSON1: content[%d] mismatch:", i)
			t.Logf("  original: %T -> %s", origElem, origElem.String())
			t.Logf("  encoded : %T -> %s", encElem, encElem.String())
			break
		}
	}

	for i := 0; i < minLen; i++ {
		origAnn, ok1 := origStream.Contents[i].(*model.Annotation)
		encAnn, ok2 := encStream.Contents[i].(*model.Annotation)
		if !ok1 || !ok2 {
			continue
		}

		origCount := len(origAnn.Contents)
		encCount := len(encAnn.Contents)
		if origCount != encCount {
			t.Logf("JSON1: annotation[%d] contents count original=%d encoded=%d", i, origCount, encCount)
		}

		innerMin := origCount
		if encCount < innerMin {
			innerMin = encCount
		}
		for j := 0; j < innerMin && j < 12; j++ {
			origInner := origAnn.Contents[j]
			encInner := encAnn.Contents[j]
			if reflect.TypeOf(origInner) != reflect.TypeOf(encInner) || origInner.String() != encInner.String() {
				t.Logf("JSON1: annotation[%d] inner[%d] diff: original=%T %s", i, j, origInner, origInner.String())
				t.Logf("                                            encoded =%T %s", encInner, encInner.String())
				break
			}
		}

		for i := 0; i < minLen; i++ {
			switch origElem := origStream.Contents[i].(type) {
			case *model.Annotation:
				if encAnn, ok2 := encStream.Contents[i].(*model.Annotation); ok2 {
					origAnn := origElem
					t.Logf("JSON1: annotation[%d] original inner types:", i)
					for idx, inner := range origAnn.Contents {
						if idx >= 12 {
							t.Logf("  ... (%d more)", len(origAnn.Contents)-idx)
							break
						}
						t.Logf("  [%d] %T -> %s", idx, inner, inner.String())
					}
					t.Logf("JSON1: annotation[%d] encoded inner types:", i)
					for idx, inner := range encAnn.Contents {
						if idx >= 12 {
							t.Logf("  ... (%d more)", len(encAnn.Contents)-idx)
							break
						}
						t.Logf("  [%d] %T -> %s", idx, inner, inner.String())
					}
					break
				}
			case *model.NewObject:
				encObj, ok2 := encStream.Contents[i].(*model.NewObject)
				if !ok2 {
					continue
				}
				className := ""
				if origElem.ClassDesc != nil {
					if desc, ok := origElem.ClassDesc.Description.(*model.NewClassDesc); ok && desc.ClassName != nil {
						className = desc.ClassName.Contents
					}
				}
				if className == "javax.management.openmbean.TabularDataSupport" {
					t.Logf("JSON1: object[%d] class=%s classData count original=%d encoded=%d", i, className, len(origElem.ClassData), len(encObj.ClassData))
					for idx := range origElem.ClassData {
						if idx >= len(encObj.ClassData) {
							break
						}
						origPV := origElem.ClassData[idx]
						encPV := encObj.ClassData[idx]
						if origPV.Type != encPV.Type {
							t.Logf("  field[%d] type mismatch original=%s encoded=%s", idx, origPV.Type.String(), encPV.Type.String())
							continue
						}
						if origPV.Type == model.Object {
							if origElemVal, ok := origPV.Value.(model.Element); ok {
								if encElemVal, ok2 := encPV.Value.(model.Element); ok2 {
									if reflect.TypeOf(origElemVal) != reflect.TypeOf(encElemVal) || origElemVal.String() != encElemVal.String() {
										t.Logf("  field[%d] element mismatch:", idx)
										t.Logf("    original=%T %s", origElemVal, origElemVal.String())
										t.Logf("    encoded =%T %s", encElemVal, encElemVal.String())
									}
								}
							}
						}
					}
				}
				if className == "com.sun.corba.se.spi.orbutil.proxy.CompositeInvocationHandlerImpl" {
					t.Logf("JSON1: object[%d] class=%s classData count original=%d encoded=%d", i, className, len(origElem.ClassData), len(encObj.ClassData))
					for idx := range origElem.ClassData {
						if idx >= len(encObj.ClassData) {
							break
						}
						origPV := origElem.ClassData[idx]
						encPV := encObj.ClassData[idx]
						if origPV.Type != encPV.Type {
							t.Logf("  field[%d] type mismatch original=%s encoded=%s", idx, origPV.Type.String(), encPV.Type.String())
							continue
						}
						if origPV.Type == model.Object {
							if origElemVal, ok := origPV.Value.(model.Element); ok {
								if encElemVal, ok2 := encPV.Value.(model.Element); ok2 {
									if reflect.TypeOf(origElemVal) != reflect.TypeOf(encElemVal) || origElemVal.String() != encElemVal.String() {
										t.Logf("  field[%d] element mismatch:", idx)
										t.Logf("    original=%T %s", origElemVal, origElemVal.String())
										t.Logf("    encoded =%T %s", encElemVal, encElemVal.String())
									}

			origDesc, okDesc1 := origElem.ClassDesc.Description.(*model.NewClassDesc)
			encDesc, okDesc2 := encObj.ClassDesc.Description.(*model.NewClassDesc)
			if okDesc1 && okDesc2 && origDesc.ClassName != nil {
				origAnnotationCount := 0
				encAnnotationCount := 0
				if origDesc.ClassAnnotation != nil {
					origAnnotationCount = len(origDesc.ClassAnnotation.Contents)
				}
				if encDesc.ClassAnnotation != nil {
					encAnnotationCount = len(encDesc.ClassAnnotation.Contents)
				}
				t.Logf("JSON1: object[%d] class %s annotation count original=%d encoded=%d", i, origDesc.ClassName.Contents, origAnnotationCount, encAnnotationCount)
				innerMin := origAnnotationCount
				if encAnnotationCount < innerMin {
					innerMin = encAnnotationCount
				}
				for j := 0; j < innerMin && j < 12; j++ {
					origAnnElem := origDesc.ClassAnnotation.Contents[j]
					encAnnElem := encDesc.ClassAnnotation.Contents[j]
					if reflect.TypeOf(origAnnElem) != reflect.TypeOf(encAnnElem) || origAnnElem.String() != encAnnElem.String() {
						t.Logf("  annotation[%d] mismatch: original=%T %s", j, origAnnElem, origAnnElem.String())
						t.Logf("                               encoded =%T %s", encAnnElem, encAnnElem.String())
						break
					}
				}
			}
								}
							}
						}
					}
				}
			}
		}
	}

	if len(origStream.Contents) != len(encStream.Contents) {
		t.Logf("JSON1: contents length differs original=%d encoded=%d", len(origStream.Contents), len(encStream.Contents))
	}
	if len(origStream.References) != len(encStream.References) {
		t.Logf("JSON1: references length differs original=%d encoded=%d", len(origStream.References), len(encStream.References))
	}
}
