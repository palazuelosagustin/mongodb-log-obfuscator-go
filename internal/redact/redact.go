package redact

import (
	"encoding/json"
	"regexp"
	"sort"
	"strings"

	"go.mongodb.org/mongo-driver/bson"
)

const Placeholder = "obfuscated payload"
const StringPlaceholder = "obfuscated string"

var commandContextKeys = set("command", "cmdObj", "originatingCommand")
var commandVerbKeys = set("find", "aggregate", "insert", "update", "delete", "findAndModify", "count", "distinct", "getMore", "explain", "create", "drop", "renameCollection", "createIndexes", "dropIndexes", "collMod")
var commandPayloadKeys = set("documents", "updates", "deletes", "query", "filter", "update", "pipeline", "let", "q", "u", "arrayFilters", "partialFilterExpression", "validator")
var applicationPayloadKeys = set("template", "templateProps", "channelOptions", "channelConfiguration", "content", "body", "html", "text", "emailBody", "emailBodyText", "smsBody", "smsBodyText", "messageBody", "pushBody", "notificationBody", "payload", "data", "cardEnding", "cardNumber", "merchant", "amount", "phone", "phoneNumber", "mobile", "mobileNumber")

var directStringKeys = subtract(union(commandPayloadKeys, applicationPayloadKeys), "documents", "updates", "deletes", "pipeline", "update", "arrayFilters", "partialFilterExpression", "validator")
var reDirectPayloadString = regexp.MustCompile(`(?P<prefix>(?:"(?:` + strings.Join(keys(directStringKeys), "|") + `)"|\b(?:` + strings.Join(keys(directStringKeys), "|") + `)\b)\s*:\s*)"(?P<value>(?:[^"\\]|\\.)*)"`)
var reDirectPayloadArray = regexp.MustCompile(`(?P<prefix>(?:"(?:documents|updates|deletes|pipeline)"|\b(?:documents|updates|deletes|pipeline)\b)\s*:\s*)\[[^\n\]]*\]`)
var reDirectPayloadObject = regexp.MustCompile(`(?P<prefix>(?:"(?:query|filter|update|let|q|u|template|templateProps|channelOptions|channelConfiguration|payload|data|body)"|\b(?:query|filter|update|let|q|u|template|templateProps|channelOptions|channelConfiguration|payload|data|body)\b)\s*:\s*)\{[^\n\}]*\}`)

// documentContainerKeys hold whole user documents wherever they appear in a
// log line or FTDC document, not only inside commands: oplog entries ("o",
// "o2" in "Applied op" lines), change-stream images and duplicate-key values.
// Their values are always replaced; field names and nesting are kept.
var documentContainerKeys = set("o", "o2", "document", "documentKey", "fullDocument", "fullDocumentBeforeChange", "updateDescription", "preImage", "postImage", "preImageDocument", "postImageDocument", "keyValue", "foundValue")

// commandSafeStringKeys are the keys inside a command whose string values are
// kept (and still pass through the shared mapping): collection, database and
// user names that the mapping replaces, enum-like options, index names and
// Extended JSON type wrappers. Every other string inside a command, such as
// "comment", is replaced: commands carry arbitrary application input.
var commandSafeStringKeys = set(
	// collection and database names (mapped)
	"find", "aggregate", "count", "distinct", "insert", "update", "delete", "findAndModify", "getMore", "create", "drop", "createIndexes", "dropIndexes", "collMod", "renameCollection", "to", "mapReduce", "listIndexes", "killCursors", "collection", "coll", "ns", "$db", "dbName", "viewOn", "db", "user",
	// options and enums
	"key", "name", "index", "hint", "mode", "level", "w", "verbosity", "locale", "caseFirst", "alternate", "maxVariable", "provenance", "apiVersion", "commitQuorum", "validationLevel", "validationAction", "timeField", "metaField", "granularity", "compression", "readPreference", "mechanism",
	// mongos client metadata
	"host", "client", "version", "type", "architecture", "platform",
	// Extended JSON type wrappers
	"$uuid", "$oid", "$date", "$numberLong", "$numberInt", "$numberDouble", "$numberDecimal", "base64", "subType",
)

// DocumentContainer reports keys whose values are user documents in any
// context.
func DocumentContainer(key string) bool {
	_, ok := documentContainerKeys[key]
	return ok
}

// CommandSafeString reports whether a string under key may be kept inside a
// command.
func CommandSafeString(key string) bool {
	_, ok := commandSafeStringKeys[key]
	return ok
}

func CommandContext(key string) bool {
	_, ok := commandContextKeys[key]
	return ok
}

func PayloadField(key string, value any, inCommand bool) bool {
	if !inCommand {
		return false
	}
	if _, ok := applicationPayloadKeys[key]; ok {
		return true
	}
	if _, ok := commandPayloadKeys[key]; ok {
		if _, isVerb := commandVerbKeys[key]; isVerb {
			_, isString := value.(string)
			return !isString
		}
		return true
	}
	return false
}

func ValueJSON(value any) any {
	switch value.(type) {
	case []any:
		return []any{Placeholder}
	case map[string]any:
		return map[string]any{"redacted": Placeholder}
	case string:
		return Placeholder
	default:
		return Placeholder
	}
}

func ValueBSON(value any) any {
	switch value.(type) {
	case bson.A, []any:
		return bson.A{Placeholder}
	case bson.D:
		return bson.D{{Key: "redacted", Value: Placeholder}}
	case string:
		return Placeholder
	default:
		return Placeholder
	}
}

func DirectText(line string) (string, int) {
	count := 0
	line = reDirectPayloadString.ReplaceAllStringFunc(line, func(match string) string {
		count++
		if colon := strings.LastIndex(match, ":"); colon >= 0 {
			return match[:colon+1] + jsonString(Placeholder)
		}
		return match
	})
	line = reDirectPayloadArray.ReplaceAllStringFunc(line, func(match string) string {
		count++
		if colon := strings.LastIndex(match, ":"); colon >= 0 {
			return match[:colon+1] + `["` + Placeholder + `"]`
		}
		return match
	})
	line = reDirectPayloadObject.ReplaceAllStringFunc(line, func(match string) string {
		count++
		if colon := strings.LastIndex(match, ":"); colon >= 0 {
			return match[:colon+1] + `{"redacted":"` + Placeholder + `"}`
		}
		return match
	})
	return line, count
}

func jsonString(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

func set(values ...string) map[string]struct{} {
	out := make(map[string]struct{}, len(values))
	for _, value := range values {
		out[value] = struct{}{}
	}
	return out
}

func union(a, b map[string]struct{}) map[string]struct{} {
	out := make(map[string]struct{}, len(a)+len(b))
	for key := range a {
		out[key] = struct{}{}
	}
	for key := range b {
		out[key] = struct{}{}
	}
	return out
}

func subtract(values map[string]struct{}, remove ...string) map[string]struct{} {
	out := make(map[string]struct{}, len(values))
	for key := range values {
		out[key] = struct{}{}
	}
	for _, key := range remove {
		delete(out, key)
	}
	return out
}

func keys(values map[string]struct{}) []string {
	out := make([]string, 0, len(values))
	for key := range values {
		out = append(out, regexp.QuoteMeta(key))
	}
	sort.Strings(out)
	return out
}
