package model

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"testing"
)

// TestClassDescDecodePath tests ClassDesc decoding path in full stream decode
func TestClassDescDecodePath(t *testing.T) {
	// Read payload
	file, err := os.Open("../../ysoserial_payloads.json")
	if err != nil {
		t.Skipf("Skipping test: cannot open ysoserial_payloads.json: %v", err)
		return
	}
	defer file.Close()

	var payloads struct {
		None map[string]struct {
			Status string `json:"status"`
			Bytes  string `json:"bytes"`
		} `json:"none"`
	}

	if err := json.NewDecoder(file).Decode(&payloads); err != nil {
		t.Fatalf("Failed to parse JSON: %v", err)
	}

	payload, exists := payloads.None["JSON1"]
	if !exists {
		t.Skipf("JSON1 payload not found")
		return
	}

	// Decode
	originalBytes, err := base64.StdEncoding.DecodeString(payload.Bytes)
	if err != nil {
		t.Fatalf("Failed to decode payload: %v", err)
	}

	reader := bytes.NewReader(originalBytes)
	stream := NewStream()
	if err := stream.Decode(reader); err != nil {
		t.Fatalf("Failed to decode: %v", err)
	}

	// Find NewEnum at position 0x2a9 (TC_ENUM)
	// Position 0x2a7: TC_REFERENCE (index 0)
	// Position 0x2a9: TC_ENUM
	// Position 0x2aa: ClassDesc starts (inline, no opcode)

	t.Logf("=== Finding NewEnum with ClassDesc at position 0x2aa ===")
	t.Logf("Total contents: %d", len(stream.Contents))
	t.Logf("Total references: %d", len(stream.References))

	// List first 10 elements in stream.Contents
	t.Logf("\nFirst 10 elements in stream.Contents:")
	for i := 0; i < len(stream.Contents) && i < 10; i++ {
		t.Logf("  Content %d: %T", i, stream.Contents[i])
	}

	// Check stream.Contents for NewEnum
	for i, content := range stream.Contents {
		if newEnum, ok := content.(*NewEnum); ok {
			t.Logf("Found NewEnum at index %d in stream.Contents", i)

			if newEnum.EnumClassDesc != nil && newEnum.EnumClassDesc.Description != nil {
				if classDesc, ok := newEnum.EnumClassDesc.Description.(*NewClassDesc); ok {
					t.Logf("  ClassDesc found:")
					t.Logf("    Class name: %q (length: %d)", classDesc.ClassName.Contents, len(classDesc.ClassName.Contents))
					t.Logf("    SerialVersionUID: 0x%016x", classDesc.SerialVersion)
					t.Logf("    Flags: 0x%02x", classDesc.Flags)
					t.Logf("    Field count: %d", len(classDesc.Fields))
					t.Logf("    OmitFlagsAndFields: %v", classDesc.OmitFlagsAndFields)

					if classDesc.ClassAnnotation != nil {
						t.Logf("    ClassAnnotation has %d elements", len(classDesc.ClassAnnotation.Contents))
						for j, elem := range classDesc.ClassAnnotation.Contents {
							if bd, ok := elem.(*BlockData); ok {
								t.Logf("      Element %d: BlockData, length=%d, data=%x", j, len(bd.Data), bd.Data[:min(len(bd.Data), 8)])
							} else {
								t.Logf("      Element %d: %T", j, elem)
							}
						}

						// Check if this is the ClassDesc at position 0x2aa
						if len(classDesc.ClassName.Contents) == 0 && classDesc.SerialVersion == 0x3f4000000000000c {
							t.Logf("    ✅ This is the ClassDesc at position 0x2aa!")
							t.Logf("    Expected: OmitFlagsAndFields=true, ClassAnnotation has BlockData")
							t.Logf("    Actual: OmitFlagsAndFields=%v, ClassAnnotation has %d elements", classDesc.OmitFlagsAndFields, len(classDesc.ClassAnnotation.Contents))

							if !classDesc.OmitFlagsAndFields {
								t.Errorf("    ❌ OmitFlagsAndFields should be true, but it's false")
							}
							if len(classDesc.ClassAnnotation.Contents) < 2 {
								t.Errorf("    ❌ ClassAnnotation should have at least 2 elements (BlockData + EndBlockData), but it has %d", len(classDesc.ClassAnnotation.Contents))
							} else {
								hasBlockData := false
								for _, elem := range classDesc.ClassAnnotation.Contents {
									if _, ok := elem.(*BlockData); ok {
										hasBlockData = true
										break
									}
								}
								if !hasBlockData {
									t.Errorf("    ❌ ClassAnnotation should contain BlockData, but it doesn't")
								}
							}
						}
					} else {
						t.Logf("    ❌ ClassAnnotation is nil!")
					}
				} else {
					t.Logf("  ClassDesc is not *NewClassDesc, type: %T", newEnum.EnumClassDesc.Description)
				}
			} else {
				t.Logf("  EnumClassDesc is nil or Description is nil")
			}
		}
	}

	// Also check stream.References
	t.Logf("\n=== Checking stream.References for NewEnum ===")
	enumCount := 0
	for i, ref := range stream.References {
		if newEnum, ok := ref.(*NewEnum); ok {
			enumCount++
			t.Logf("Found NewEnum at index %d in stream.References", i)

			if newEnum.EnumClassDesc != nil && newEnum.EnumClassDesc.Description != nil {
				if classDesc, ok := newEnum.EnumClassDesc.Description.(*NewClassDesc); ok {
					if len(classDesc.ClassName.Contents) == 0 && classDesc.SerialVersion == 0x3f4000000000000c {
						t.Logf("  ✅ Found ClassDesc at position 0x2aa in stream.References!")
						t.Logf("    OmitFlagsAndFields: %v", classDesc.OmitFlagsAndFields)
						if classDesc.ClassAnnotation != nil {
							t.Logf("    ClassAnnotation has %d elements", len(classDesc.ClassAnnotation.Contents))
						}
					}
				}
			}
		}
	}

	t.Logf("\nTotal NewEnum found in stream.References: %d", enumCount)

	// Search for ClassDesc with SerialVersionUID 0x3f4000000000000c
	t.Logf("\n=== Searching for ClassDesc with SerialVersionUID 0x3f4000000000000c ===")
	foundTarget := false
	for i, ref := range stream.References {
		if classDesc, ok := ref.(*NewClassDesc); ok {
			if len(classDesc.ClassName.Contents) == 0 && classDesc.SerialVersion == 0x3f4000000000000c {
				t.Logf("✅ Found target ClassDesc at index %d!", i)
				t.Logf("  Class name: %q (length: %d)", classDesc.ClassName.Contents, len(classDesc.ClassName.Contents))
				t.Logf("  SerialVersionUID: 0x%016x", classDesc.SerialVersion)
				t.Logf("  Flags: 0x%02x", classDesc.Flags)
				t.Logf("  Field count: %d", len(classDesc.Fields))
				t.Logf("  OmitFlagsAndFields: %v", classDesc.OmitFlagsAndFields)
				if classDesc.ClassAnnotation != nil {
					t.Logf("  ClassAnnotation has %d elements", len(classDesc.ClassAnnotation.Contents))
					for j, elem := range classDesc.ClassAnnotation.Contents {
						if j >= 10 {
							t.Logf("    ... and %d more elements", len(classDesc.ClassAnnotation.Contents)-10)
							break
						}
						if bd, ok := elem.(*BlockData); ok {
							t.Logf("      Element %d: BlockData, length=%d, data=%x", j, len(bd.Data), bd.Data[:min(len(bd.Data), 8)])
						} else {
							t.Logf("      Element %d: %T", j, elem)
						}
					}
				} else {
					t.Logf("  ❌ ClassAnnotation is nil!")
				}
				foundTarget = true
			}
		}
	}

	if !foundTarget {
		t.Logf("❌ Target ClassDesc (SerialVersionUID 0x3f4000000000000c) not found in stream.References")
		t.Logf("This suggests the ClassDesc was not decoded correctly, or it's not in stream.References")
	}

	// Check what's at index 0 (referenced by TC_REFERENCE at 0x2a7)
	if len(stream.References) > 0 {
		t.Logf("\n=== Element at index 0 (referenced by TC_REFERENCE at 0x2a7) ===")
		ref0 := stream.References[0]
		t.Logf("Type: %T", ref0)
		if newEnum, ok := ref0.(*NewEnum); ok {
			t.Logf("✅ Index 0 is NewEnum!")
			if newEnum.EnumClassDesc != nil && newEnum.EnumClassDesc.Description != nil {
				if classDesc, ok := newEnum.EnumClassDesc.Description.(*NewClassDesc); ok {
					t.Logf("  ClassDesc found:")
					t.Logf("    Class name: %q (length: %d)", classDesc.ClassName.Contents, len(classDesc.ClassName.Contents))
					t.Logf("    SerialVersionUID: 0x%016x", classDesc.SerialVersion)
					t.Logf("    OmitFlagsAndFields: %v", classDesc.OmitFlagsAndFields)
					if classDesc.ClassAnnotation != nil {
						t.Logf("    ClassAnnotation has %d elements", len(classDesc.ClassAnnotation.Contents))
					}
				}
			}
		} else if classDesc, ok := ref0.(*NewClassDesc); ok {
			t.Logf("Index 0 is NewClassDesc!")
			t.Logf("  Class name: %q (length: %d)", classDesc.ClassName.Contents, len(classDesc.ClassName.Contents))
			t.Logf("  SerialVersionUID: 0x%016x", classDesc.SerialVersion)
			t.Logf("  Flags: 0x%02x", classDesc.Flags)
			t.Logf("  Field count: %d", len(classDesc.Fields))
			t.Logf("  OmitFlagsAndFields: %v", classDesc.OmitFlagsAndFields)
			if classDesc.ClassAnnotation != nil {
				t.Logf("  ClassAnnotation has %d elements", len(classDesc.ClassAnnotation.Contents))
				for j, elem := range classDesc.ClassAnnotation.Contents {
					if j >= 5 {
						t.Logf("    ... and %d more elements", len(classDesc.ClassAnnotation.Contents)-5)
						break
					}
					if bd, ok := elem.(*BlockData); ok {
						t.Logf("      Element %d: BlockData, length=%d, data=%x", j, len(bd.Data), bd.Data[:min(len(bd.Data), 8)])
					} else {
						t.Logf("      Element %d: %T", j, elem)
					}
				}
			}

			// Check if this is the ClassDesc at position 0x2aa
			if len(classDesc.ClassName.Contents) == 0 && classDesc.SerialVersion == 0x3f4000000000000c {
				t.Logf("  ✅ This is the ClassDesc at position 0x2aa!")
			}
		} else {
			t.Logf("Index 0 is NOT NewEnum or NewClassDesc, it's %T", ref0)
		}
	}
}
