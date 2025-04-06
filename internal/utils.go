package internal

import (
	"fmt"
	"strings"
	"time"
)

// FormatTime formats microseconds into a human-readable string.
func FormatTime(microseconds uint32) string {
	if microseconds < 1000 {
		return fmt.Sprintf("%d µs", microseconds)
	}

	var value float64
	var unit string

	if microseconds < 1000000 {
		value = float64(microseconds) / 1000
		unit = "ms"
	} else {
		duration := time.Duration(microseconds) * time.Microsecond
		value = duration.Seconds()
		unit = "s"
	}

	// Trim trailing zeros and dot
	formatted := strings.TrimRight(strings.TrimRight(fmt.Sprintf("%.5g", value), "0"), ".")

	return fmt.Sprintf("%s %s", formatted, unit)
}
