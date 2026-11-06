// Package timerange is the --from/--to window: From is inclusive, To is
// exclusive, a zero bound is open. Times are parsed like mongodb-logstat and
// mongodb-ftdcstat parse them.
package timerange

import (
	"fmt"
	"time"
)

type Range struct {
	From, To time.Time
}

// Set reports whether a bound was given.
func (r Range) Set() bool { return !r.From.IsZero() || !r.To.IsZero() }

// Contains reports whether t is in [From, To).
func (r Range) Contains(t time.Time) bool {
	return (r.From.IsZero() || !t.Before(r.From)) && (r.To.IsZero() || t.Before(r.To))
}

// Overlaps reports whether [start, end) meets the range.
func (r Range) Overlaps(start, end time.Time) bool {
	return (r.To.IsZero() || start.Before(r.To)) && (r.From.IsZero() || end.After(r.From))
}

// Parse accepts RFC3339 (2026-11-04T13:30:00Z, with an offset or fraction)
// or a UTC time without zone (2026-11-04T13:30:00, 2026-11-04T13:30,
// 2026-11-04 13:30, 2026-11-04).
func Parse(value string) (time.Time, error) {
	for _, layout := range []string{time.RFC3339Nano, "2006-01-02 15:04:05Z07:00"} {
		if t, err := time.Parse(layout, value); err == nil {
			return t, nil
		}
	}
	for _, layout := range []string{"2006-01-02T15:04:05", "2006-01-02T15:04", "2006-01-02 15:04:05", "2006-01-02 15:04", "2006-01-02"} {
		if t, err := time.ParseInLocation(layout, value, time.UTC); err == nil {
			return t, nil
		}
	}
	return time.Time{}, fmt.Errorf("%q: expected RFC3339 (2026-11-04T13:30:00Z) or a UTC time without zone (2026-11-04T13:30, 2026-11-04)", value)
}
