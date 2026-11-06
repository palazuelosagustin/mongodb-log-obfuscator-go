// Package logline separates a structured MongoDB log document from a prefix
// added by syslog/journald, kubectl --timestamps or docker logs.
package logline

import (
	"bytes"
	"time"

	"github.com/palazuelosagustin/mongodb-log-obfuscator-go/internal/timerange"
)

// MaxPrefix bounds how far into a line the JSON document may start.
const MaxPrefix = 256

var docStart = []byte(`{"t":{"$date"`)

// Split returns the prefix before the structured log document and the
// document itself. A line that is a document returns an empty prefix; a line
// without one returns ok=false.
func Split(line []byte) (prefix, doc []byte, ok bool) {
	if bytes.HasPrefix(line, docStart) {
		return nil, line, true
	}
	limit := len(line)
	if limit > MaxPrefix+len(docStart) {
		limit = MaxPrefix + len(docStart)
	}
	if i := bytes.Index(line[:limit], docStart); i > 0 {
		return line[:i], line[i:], true
	}
	return nil, line, false
}

var timePrefix = []byte(`{"t":{"$date":"`)

// Timestamp returns the "t" of a structured log document without parsing
// the rest of it.
func Timestamp(doc []byte) (time.Time, bool) {
	if !bytes.HasPrefix(doc, timePrefix) {
		return time.Time{}, false
	}
	rest := doc[len(timePrefix):]
	end := bytes.IndexByte(rest, '"')
	if end < 0 {
		return time.Time{}, false
	}
	t, err := time.Parse(time.RFC3339Nano, string(rest[:end]))
	if err != nil {
		return time.Time{}, false
	}
	return t, true
}

// Keep reports whether a log line is inside r. Lines without a timestamp
// (configuration files, command output, continuation lines) are kept.
func Keep(line []byte, r timerange.Range) bool {
	if !r.Set() {
		return true
	}
	_, doc, ok := Split(line)
	if !ok {
		return true
	}
	t, ok := Timestamp(doc)
	if !ok {
		return true
	}
	return r.Contains(t)
}
