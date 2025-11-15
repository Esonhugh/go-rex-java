package model

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"testing"
)

// TestAnalyzeAllBlockDataIssues analyzes all three problematic payloads
func TestAnalyzeAllBlockDataIssues(t *testing.T) {
	// Read payloads
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

	problematic := []struct {
		name         string
		firstDiffPos int
	}{
		{"JSON1", 0x2b4},
		{"MozillaRhino1", 0x72f},
		{"MozillaRhino2", 0x34a},
	}

	for _, p := range problematic {
		t.Run(p.name, func(t *testing.T) {
			payload, exists := payloads.None[p.name]
			if !exists {
				t.Skipf("Payload %s not found", p.name)
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

			t.Logf("=== Analyzing %s ===", p.name)
			t.Logf("First difference at position 0x%04x", p.firstDiffPos)
			t.Logf("Total contents: %d", len(stream.Contents))
			t.Logf("Total references: %d", len(stream.References))

			// Find all ClassDesc with ClassAnnotation
			t.Logf("\nFinding ClassDesc with ClassAnnotation:")
			foundCount := 0
			enumCount := 0
			t.Logf("Checking all contents (%d items)...", len(stream.Contents))
			for i, content := range stream.Contents {
				contentType := fmt.Sprintf("%T", content)
				if i < 5 {
					t.Logf("  Content %d: %s", i, contentType)
				}
				if newEnum, ok := content.(*NewEnum); ok {
					enumCount++
					t.Logf("  Found NewEnum at index %d", i)
					if newEnum.EnumClassDesc != nil && newEnum.EnumClassDesc.Description != nil {
						if classDesc, ok := newEnum.EnumClassDesc.Description.(*NewClassDesc); ok {
							if classDesc.ClassAnnotation != nil {
								foundCount++
								t.Logf("\n  ClassDesc #%d (from NewEnum at index %d):", foundCount, i)
								t.Logf("    OmitFlagsAndFields: %v", classDesc.OmitFlagsAndFields)
								t.Logf("    ClassAnnotation has %d elements", len(classDesc.ClassAnnotation.Contents))

								// Check if this annotation contains BlockData at the difference position
								blockDataCount := 0
								for j, elem := range classDesc.ClassAnnotation.Contents {
									if bd, ok := elem.(*BlockData); ok {
										blockDataCount++
										t.Logf("      Element %d: BlockData, length=%d, data=%x", j, len(bd.Data), bd.Data[:min(len(bd.Data), 8)])
									} else {
										elemType := fmt.Sprintf("%T", elem)
										t.Logf("      Element %d: %s", j, elemType)
									}
								}
								t.Logf("    Total BlockData elements: %d", blockDataCount)
							}
						}
					}
				} else if classDesc, ok := content.(*NewClassDesc); ok {
					if classDesc.ClassAnnotation != nil {
						foundCount++
						t.Logf("\n  ClassDesc #%d (direct at index %d):", foundCount, i)
						t.Logf("    OmitFlagsAndFields: %v", classDesc.OmitFlagsAndFields)
						t.Logf("    ClassAnnotation has %d elements", len(classDesc.ClassAnnotation.Contents))

						// Check if this annotation contains BlockData at the difference position
						blockDataCount := 0
						for j, elem := range classDesc.ClassAnnotation.Contents {
							if bd, ok := elem.(*BlockData); ok {
								blockDataCount++
								t.Logf("      Element %d: BlockData, length=%d, data=%x", j, len(bd.Data), bd.Data[:min(len(bd.Data), 8)])
							} else {
								elemType := fmt.Sprintf("%T", elem)
								t.Logf("      Element %d: %s", j, elemType)
							}
						}
						t.Logf("    Total BlockData elements: %d", blockDataCount)
					}
				}
			}
			// Also check stream.References
			t.Logf("\nChecking stream.References (%d items)...", len(stream.References))
			for i, ref := range stream.References {
				if newEnum, ok := ref.(*NewEnum); ok {
					if newEnum.EnumClassDesc != nil && newEnum.EnumClassDesc.Description != nil {
						if classDesc, ok := newEnum.EnumClassDesc.Description.(*NewClassDesc); ok {
							if classDesc.ClassAnnotation != nil {
								foundCount++
								t.Logf("  Found ClassDesc in references at index %d (from NewEnum)", i)
								t.Logf("    OmitFlagsAndFields: %v", classDesc.OmitFlagsAndFields)
								t.Logf("    ClassAnnotation has %d elements", len(classDesc.ClassAnnotation.Contents))
							}
						}
					}
				} else if classDesc, ok := ref.(*NewClassDesc); ok {
					if classDesc.ClassAnnotation != nil {
						foundCount++
						t.Logf("  Found ClassDesc in references at index %d (direct)", i)
						t.Logf("    OmitFlagsAndFields: %v", classDesc.OmitFlagsAndFields)
						t.Logf("    ClassAnnotation has %d elements", len(classDesc.ClassAnnotation.Contents))

						// Always show first few ClassAnnotation elements for debugging
						if len(classDesc.ClassAnnotation.Contents) > 0 {
							t.Logf("    ClassAnnotation elements:")
							for j, elem := range classDesc.ClassAnnotation.Contents {
								if j >= 5 { // Only show first 5 elements
									t.Logf("      ... and %d more elements", len(classDesc.ClassAnnotation.Contents)-5)
									break
								}
								if bd, ok := elem.(*BlockData); ok {
									t.Logf("        Element %d: BlockData, length=%d, data=%x", j, len(bd.Data), bd.Data[:min(len(bd.Data), 8)])
								} else {
									elemType := fmt.Sprintf("%T", elem)
									t.Logf("        Element %d: %s", j, elemType)
								}
							}
						}

						// Check if this ClassDesc might be the one at position 0x2aa
						// Look for ClassDesc with empty class name and SerialVersionUID 0x3f4000000000000c
						if len(classDesc.ClassName.Contents) == 0 && classDesc.SerialVersion == 0x3f4000000000000c {
							t.Logf("    ⚠️  This might be the ClassDesc at position 0x2aa!")
							t.Logf("      Class name: %q", classDesc.ClassName.Contents)
							t.Logf("      SerialVersionUID: 0x%016x", classDesc.SerialVersion)
							t.Logf("      Flags: 0x%02x", classDesc.Flags)
							t.Logf("      Field count: %d", len(classDesc.Fields))
							t.Logf("      ClassAnnotation elements:")
							for j, elem := range classDesc.ClassAnnotation.Contents {
								if bd, ok := elem.(*BlockData); ok {
									t.Logf("        Element %d: BlockData, length=%d, data=%x", j, len(bd.Data), bd.Data[:min(len(bd.Data), 8)])
								} else {
									t.Logf("        Element %d: %T", j, elem)
								}
							}
						}
					}
				}
			}

			t.Logf("\nTotal NewEnum found: %d", enumCount)
			t.Logf("Total ClassDesc with ClassAnnotation found: %d", foundCount)
		})
	}
}
