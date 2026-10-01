// Package secret handles secret values kept on the host.
// The capsule record stores names. Captured output stores neither the value
// nor a copy that a peer can read.
package secret

import "strings"

// Redact replaces each value in s. Longer values are replaced first.
func Redact(s string, values []string) string {
	ordered := append([]string(nil), values...)
	for i := 1; i < len(ordered); i++ {
		for j := i; j > 0 && len(ordered[j]) > len(ordered[j-1]); j-- {
			ordered[j], ordered[j-1] = ordered[j-1], ordered[j]
		}
	}
	for _, value := range ordered {
		if value == "" {
			continue
		}
		s = strings.ReplaceAll(s, value, "[redacted]")
	}
	return s
}

// Contains reports whether body includes any value.
func Contains(body string, values []string) bool {
	for _, value := range values {
		if value != "" && strings.Contains(body, value) {
			return true
		}
	}
	return false
}
