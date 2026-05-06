package rules

import "math"

func shannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0.0
	}

	// Count the frequency of each character
	frequency := make(map[rune]float64)
	for _, char := range s {
		frequency[char]++
	}

	// Calculate the total number of characters
	total := float64(len(s))

	// Calculate entropy
	var entropy float64
	for _, count := range frequency {
		probability := count / total
		entropy += probability * math.Log2(probability)
	}

	return -entropy // Negate the sum as entropy is positive
}
