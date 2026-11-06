package processor

import (
	"regexp"

	"github.com/palazuelosagustin/mongodb-log-obfuscator-go/internal/redact"
)

// Aggregation pipelines mix application values with structure needed for
// diagnosis. Stages that filter on values ($match and friends) are redacted
// like any payload. In other stages field references ("$amount", "$$ROOT"),
// numbers ($limit, $sort and $project flags) and booleans are kept, the
// collection names of $lookup/$unionWith/$out/$merge are mapped, the field
// names of $lookup/$graphLookup are kept, and any other string is replaced.

var filterStages = map[string]bool{"$match": true, "$geoNear": true, "$search": true, "$searchMeta": true, "$vectorSearch": true, "$documents": true, "$redact": true}

// Keys of stage specifications whose string values are collection names or
// field names, not data.
var (
	stageCollectionKeys = map[string]bool{"from": true, "coll": true, "into": true, "db": true}
	stageFieldKeys      = map[string]bool{"localField": true, "foreignField": true, "as": true, "connectFromField": true, "connectToField": true, "depthField": true, "includeArrayIndex": true, "path": true, "on": true}
	stageFilterKeys     = map[string]bool{"restrictSearchWithMatch": true, "query": true}
)

var reFieldRef = regexp.MustCompile(`^\$\$?[A-Za-z_][\w.]*$`)

func (o *obfuscator) pipelineJSON(v any) (any, int) {
	stages, ok := v.([]any)
	if !ok {
		return redactJSONValue(v)
	}
	out := make([]any, len(stages))
	total := 0
	for i, stage := range stages {
		obj, ok := stage.(jsonObject)
		if !ok {
			repl, n := redactJSONValue(stage)
			out[i], total = repl, total+n
			continue
		}
		res := make(jsonObject, len(obj))
		for j, m := range obj {
			res[j].key = m.key
			repl, n := o.stageJSON(m.key, m.value)
			res[j].value, total = repl, total+n
		}
		out[i] = res
	}
	return out, total
}

func (o *obfuscator) stageJSON(op string, arg any) (any, int) {
	if filterStages[op] {
		return redactJSONValue(arg)
	}
	switch op {
	case "$facet":
		obj, ok := arg.(jsonObject)
		if !ok {
			return redactJSONValue(arg)
		}
		res := make(jsonObject, len(obj))
		total := 0
		for i, m := range obj {
			res[i].key = m.key
			repl, n := o.pipelineJSON(m.value)
			res[i].value, total = repl, total+n
		}
		return res, total
	case "$out", "$unionWith", "$merge", "$lookup", "$graphLookup":
		if s, ok := arg.(string); ok {
			return o.values.Apply(s), 0 // collection name
		}
	}
	return o.stageSpecJSON(arg, "")
}

// stageSpecJSON walks a stage specification; key is the key the value is
// stored under.
func (o *obfuscator) stageSpecJSON(v any, key string) (any, int) {
	switch x := v.(type) {
	case jsonObject:
		res := make(jsonObject, len(x))
		total := 0
		for i, m := range x {
			res[i].key = m.key
			var repl any
			var n int
			switch {
			case m.key == "pipeline" || (m.key == "whenMatched" && isArray(m.value)):
				repl, n = o.pipelineJSON(m.value)
			case stageFilterKeys[m.key] || filterStages[m.key]:
				repl, n = redactJSONValue(m.value)
			default:
				repl, n = o.stageSpecJSON(m.value, m.key)
			}
			res[i].value, total = repl, total+n
		}
		return res, total
	case []any:
		res := make([]any, len(x))
		total := 0
		for i, item := range x {
			repl, n := o.stageSpecJSON(item, key)
			res[i], total = repl, total+n
		}
		return res, total
	case string:
		switch {
		case stageCollectionKeys[key]:
			return o.values.Apply(x), 0
		case stageFieldKeys[key], reFieldRef.MatchString(x):
			return x, 0
		case key == "whenMatched" || key == "whenNotMatched":
			return x, 0 // "merge", "replace", "fail", ...
		}
		after := redact.Token(x)
		return after, countStringChange(x, after)
	default:
		return v, 0 // numbers, booleans, null
	}
}

func isArray(v any) bool {
	_, ok := v.([]any)
	return ok
}
