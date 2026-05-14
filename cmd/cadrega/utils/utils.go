// Package utils implements utility functions to:
// - Read the contents of a file
package utils

import (
	"io"
	"os"
)

func ReadFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	// Close the file
	// The error can be ignored
	defer func() { _ = f.Close() }()

	// Read the file content
	b, err := io.ReadAll(f)
	if err != nil {
		return "", err
	}

	return string(b), nil
}
