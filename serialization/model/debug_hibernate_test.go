package model

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"testing"
)

// TestDebugHibernatePayload is a helper test (skipped by default) that prints out
// the decoded elements for the Hibernate1 payload. It can be run manually when
// investigating encoding mismatches:
//
//	go test ./serialization/model -run TestDebugHibernatePayload -v
func TestDebugHibernatePayload(t *testing.T) {
	if os.Getenv("GO_REX_DEBUG") == "" {
		t.Skip("set GO_REX_DEBUG=1 to run")
	}

	data, err := os.ReadFile("../../ysoserial_payloads.json")
	if err != nil {
		t.Fatalf("read json: %v", err)
	}

	var payloads struct {
		None map[string]struct {
			Status string `json:"status"`
			Bytes  string `json:"bytes"`
		} `json:"none"`
	}
	if err := json.Unmarshal(data, &payloads); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	payload := payloads.None["Hibernate1"]
	raw, err := base64.StdEncoding.DecodeString(payload.Bytes)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}

	stream := NewStream()
	if err := stream.Decode(NewByteReader(raw)); err != nil {
		t.Fatalf("decode stream: %v", err)
	}

	t.Logf("contents: %d, references: %d", len(stream.Contents), len(stream.References))
	for i, elem := range stream.Contents {
		if i > 20 {
			t.Logf("... (%d more contents)", len(stream.Contents)-i)
			break
		}
		t.Logf("content[%d]: %T -> %s", i, elem, elem.String())
	}

	for i, ref := range stream.References {
		if i > 30 {
			t.Logf("... (%d more references)", len(stream.References)-i)
			break
		}
		t.Logf("reference[%d]=%T -> %s", i, ref, ref.String())
	}

	// Inspect TemplatesImpl class descriptor
	for _, ref := range stream.References {
		desc, ok := ref.(*NewClassDesc)
		if !ok || desc.ClassName == nil {
			continue
		}
		if desc.ClassName.Contents == "com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl" {
			t.Logf("TemplatesImpl fields (%d)", len(desc.Fields))
			for idx, field := range desc.Fields {
				name := "<nil>"
				if field.Name != nil {
					name = field.Name.Contents
				}
				t.Logf("  field[%d]: name=%s type=%s fieldType=%v", idx, name, field.Type, field.FieldType)
			}
		}
	}
}
