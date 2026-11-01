package careerzk

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
)

const maxJSONBytes = 64 * 1024

// Reject ambiguous duplicate keys, excessive nesting, unknown fields, and
// multiple JSON values rather than normalizing them silently.
func uniqueJSON(d *json.Decoder, depth int) error {
	if depth > 16 {
		return fmt.Errorf("%w: JSON nesting", ErrInput)
	}
	t, err := d.Token()
	if err != nil {
		return err
	}
	if delim, ok := t.(json.Delim); ok {
		switch delim {
		case '{':
			seen := map[string]bool{}
			for d.More() {
				key, err := d.Token()
				if err != nil {
					return err
				}
				name, ok := key.(string)
				// encoding/json matches struct fields without regard to case.
				// Treat those aliases as duplicates too.
				canonical := strings.ToLower(name)
				if !ok || seen[canonical] {
					return fmt.Errorf("%w: duplicate or invalid JSON key", ErrInput)
				}
				seen[canonical] = true
				if err := uniqueJSON(d, depth+1); err != nil {
					return err
				}
			}
		case '[':
			for d.More() {
				if err := uniqueJSON(d, depth+1); err != nil {
					return err
				}
			}
		default:
			return fmt.Errorf("%w: unexpected JSON delimiter", ErrInput)
		}
		_, err = d.Token()
	}
	return err
}

func DecodeJSON(raw []byte, dst any) error {
	if len(raw) > maxJSONBytes {
		return fmt.Errorf("%w: JSON too large", ErrInput)
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	if err := uniqueJSON(d, 0); err != nil {
		return fmt.Errorf("%w: JSON syntax: %v", ErrInput, err)
	}
	if _, err := d.Token(); err != io.EOF {
		return fmt.Errorf("%w: trailing JSON data", ErrInput)
	}
	d = json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(dst); err != nil {
		return fmt.Errorf("%w: JSON schema: %v", ErrInput, err)
	}
	return nil
}

func ReadJSON(path string, dst any) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, maxJSONBytes+1))
	if err != nil {
		return err
	}
	return DecodeJSON(b, dst)
}

func writeNew(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	_, writeErr := f.Write(data)
	closeErr := f.Close()
	if writeErr != nil {
		return writeErr
	}
	return closeErr
}

func WriteJSON(path string, value any) error {
	b, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	return writeNew(path, append(b, '\n'))
}
