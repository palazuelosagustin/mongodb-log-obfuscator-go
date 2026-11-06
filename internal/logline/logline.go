// Package logline separates a structured MongoDB log document from a prefix
// added by syslog/journald, kubectl --timestamps or docker logs.
package logline

import "bytes"

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
