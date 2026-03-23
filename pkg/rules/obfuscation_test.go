package rules

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDetectASCIISmuggling(t *testing.T) {
	data := "\U000E0048\U000E0065\U000E006C\U000E006C\U000E006F\U000E002C\U000E0020\U000E0077\U000E006F\U000E0072\U000E006C\U000E0064\U000E0021"
	result := DetectASCIISmuggling(data)
	assert.Equal(t, "Hello, world!", result)
}

func TestDetectASCIISmugglingNoSmuggling(t *testing.T) {
	data := "Hello, world!"
	result := DetectASCIISmuggling(data)
	assert.Equal(t, "", result)
}

func TestDetectASCIISmugglingEmptyData(t *testing.T) {
	result := DetectASCIISmuggling("")
	assert.Equal(t, "", result)
}
