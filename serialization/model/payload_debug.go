package model

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
)

// DebugPayload analyzes a payload byte by byte
func DebugPayload(payloadBytes []byte) error {
	fmt.Printf("=== Payload Debug Analysis ===\n")
	fmt.Printf("Total size: %d bytes\n", len(payloadBytes))
	fmt.Printf("Magic: 0x%02x%02x\n", payloadBytes[0], payloadBytes[1])
	fmt.Printf("Version: 0x%02x%02x\n", payloadBytes[2], payloadBytes[3])
	
	elementCount := 0
	
	reader := NewByteReader(payloadBytes[4:])
	stream := NewStream()
	
	fmt.Printf("\n=== Decoding Elements ===\n")
	
	for {
		// Get current reader position (offset from start of data, add 4 for magic+version)
		currentReaderPos := 4 + reader.Position()
		
		if currentReaderPos >= len(payloadBytes) {
			break
		}
		
		// Peek next byte at current reader position
		opcode := payloadBytes[currentReaderPos]
		fmt.Printf("\n[Position %d (absolute: %d)] Opcode: 0x%02x", reader.Position(), currentReaderPos, opcode)
		
		// Check if it's a valid opcode
		validOpcodes := map[byte]string{
			0x70: "TC_NULL",
			0x71: "TC_REFERENCE",
			0x72: "TC_CLASSDESC",
			0x73: "TC_OBJECT",
			0x74: "TC_STRING",
			0x75: "TC_ARRAY",
			0x76: "TC_CLASS",
			0x77: "TC_BLOCKDATA",
			0x78: "TC_ENDBLOCKDATA",
			0x79: "TC_RESET",
			0x7A: "TC_BLOCKDATALONG",
			0x7B: "TC_EXCEPTION",
			0x7C: "TC_LONGSTRING",
			0x7D: "TC_PROXYCLASSDESC",
			0x7E: "TC_ENUM",
		}
		
		if name, ok := validOpcodes[opcode]; ok {
			fmt.Printf(" (%s)\n", name)
		} else if opcode == 0 {
			fmt.Printf(" (ZERO BYTE - POTENTIAL ERROR!)\n")
			// Show context
			start := max(0, currentReaderPos-20)
			end := min(len(payloadBytes), currentReaderPos+20)
			fmt.Printf("Context bytes: ")
			for i := start; i < end; i++ {
				if i == currentReaderPos {
					fmt.Printf("[%02x]", payloadBytes[i])
				} else {
					fmt.Printf("%02x ", payloadBytes[i])
				}
			}
			fmt.Printf("\n")
			// Show what we decoded so far
			fmt.Printf("Decoded %d elements so far\n", elementCount)
			fmt.Printf("Reader has consumed %d bytes (offset: %d)\n", reader.Position(), reader.Position())
			return fmt.Errorf("found zero byte at position %d", currentReaderPos)
		} else {
			fmt.Printf(" (UNKNOWN OPCODE)\n")
			start := max(0, currentReaderPos-20)
			end := min(len(payloadBytes), currentReaderPos+20)
			fmt.Printf("Context bytes: ")
			for i := start; i < end; i++ {
				if i == currentReaderPos {
					fmt.Printf("[%02x]", payloadBytes[i])
				} else {
					fmt.Printf("%02x ", payloadBytes[i])
				}
			}
			fmt.Printf("\n")
		}
		
		// Record position before decode
		posBefore := reader.Position()
		
		// Try to decode
		element, err := DecodeElement(reader, stream)
		if err != nil {
			fmt.Printf("  ERROR: %v\n", err)
			fmt.Printf("  Failed at absolute position %d (reader offset: %d)\n", currentReaderPos, posBefore)
			fmt.Printf("  Bytes consumed before error: %d\n", reader.Position()-posBefore)
			// Show next few bytes
			nextStart := currentReaderPos
			nextEnd := min(len(payloadBytes), nextStart+30)
			fmt.Printf("  Next bytes in stream: ")
			for i := nextStart; i < nextEnd; i++ {
				fmt.Printf("%02x ", payloadBytes[i])
			}
			fmt.Printf("\n")
			return err
		}
		
		posAfter := reader.Position()
		bytesConsumed := posAfter - posBefore
		
		elementCount++
		fmt.Printf("  Successfully decoded: %T (consumed %d bytes)\n", element, bytesConsumed)
		
		// Show what was read
		if bytesConsumed > 0 && bytesConsumed < 50 {
			fmt.Printf("  Bytes read: ")
			for i := 0; i < bytesConsumed && (posBefore+i) < len(reader.data); i++ {
				fmt.Printf("%02x ", reader.data[posBefore+i])
			}
			fmt.Printf("\n")
		}
		
		stream.Contents = append(stream.Contents, element)
		
		// Safety check - don't loop forever
		if elementCount > 100 {
			fmt.Printf("  Stopped after 100 elements\n")
			break
		}
		
		// Check if we've reached end
		if reader.Position() >= len(reader.data) {
			break
		}
	}
	
	fmt.Printf("\n=== Summary ===\n")
	fmt.Printf("Successfully decoded %d elements\n", elementCount)
	finalPos := 4 + reader.Position()
	fmt.Printf("Final position: %d / %d\n", finalPos, len(payloadBytes))
	
	return nil
}

// ByteReader wraps a byte slice as io.Reader and tracks position
type ByteReader struct {
	data      []byte
	offset    int
	readCount []int // Track each read size
}

func NewByteReader(data []byte) *ByteReader {
	return &ByteReader{
		data:      data,
		offset:    0,
		readCount: make([]int, 0),
	}
}

func (br *ByteReader) Read(p []byte) (n int, err error) {
	if br.offset >= len(br.data) {
		return 0, io.EOF
	}
	n = copy(p, br.data[br.offset:])
	br.offset += n
	br.readCount = append(br.readCount, n)
	return n, nil
}

func (br *ByteReader) Position() int {
	return br.offset
}

func (br *ByteReader) ReadHistory() []int {
	return br.readCount
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func estimateElementSize(elem Element, data []byte, start int) int {
	// Rough estimate - this is not accurate but helps with debugging
	switch elem.(type) {
	case *NullReference:
		return 1
	case *EndBlockData:
		return 1
	case *Reset:
		return 1
	case *BlockData:
		if bd, ok := elem.(*BlockData); ok && len(bd.Data) > 0 {
			return 1 + 1 + len(bd.Data)
		}
		return 2
	default:
		return 10 // Default estimate
	}
}

// DebugPayloadFromFile loads and debugs a payload from JSON file
func DebugPayloadFromFile(jsonPath string, payloadName string) error {
	data, err := os.ReadFile(jsonPath)
	if err != nil {
		return fmt.Errorf("failed to read file: %w", err)
	}
	
	var payloads map[string]interface{}
	if err := json.Unmarshal(data, &payloads); err != nil {
		return fmt.Errorf("failed to parse JSON: %w", err)
	}
	
	none, ok := payloads["none"].(map[string]interface{})
	if !ok {
		return fmt.Errorf("cannot find 'none' key")
	}
	
	payload, ok := none[payloadName].(map[string]interface{})
	if !ok {
		return fmt.Errorf("cannot find payload %s", payloadName)
	}
	
	bytesStr, ok := payload["bytes"].(string)
	if !ok {
		return fmt.Errorf("cannot find bytes")
	}
	
	bytesData, err := base64.StdEncoding.DecodeString(bytesStr)
	if err != nil {
		return fmt.Errorf("failed to decode base64: %w", err)
	}
	
	return DebugPayload(bytesData)
}

