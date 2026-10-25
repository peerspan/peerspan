package linking

import "time"

// legacyStamp preserves the UTC nanoseconds emitted in existing signed facts.
// New linking objects continue to use stamp's exact whole-second grammar.
func legacyStamp(value string) (time.Time, error) {
	if len(value) == 20 {
		return stamp(value)
	}
	if len(value) < 22 || len(value) > 30 || value[19] != '.' || value[len(value)-1] != 'Z' {
		return time.Time{}, invalid()
	}
	if _, err := stamp(value[:19] + "Z"); err != nil {
		return time.Time{}, err
	}
	for _, digit := range value[20 : len(value)-1] {
		if digit < '0' || digit > '9' {
			return time.Time{}, invalid()
		}
	}
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		return time.Time{}, invalid()
	}
	return parsed, nil
}
