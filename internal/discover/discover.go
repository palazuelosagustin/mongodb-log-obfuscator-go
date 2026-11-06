package discover

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"

	"github.com/agustinp/mongodb-log-obfuscator-go/internal/ftdc"
	"github.com/agustinp/mongodb-log-obfuscator-go/internal/logline"
	"github.com/agustinp/mongodb-log-obfuscator-go/internal/redact"
	"github.com/agustinp/mongodb-log-obfuscator-go/internal/registry"
	"go.mongodb.org/mongo-driver/bson"
)

type Result struct {
	Collector *registry.Collector
	Count     int
	Warnings  []string
}

type Scanner struct {
	c        *registry.Collector
	warnings []string
}

func LogFile(path string) (Result, error) {
	s := &Scanner{c: registry.NewCollector()}
	f, err := os.Open(path)
	if err != nil {
		return Result{}, err
	}
	defer f.Close()
	r := bufio.NewReaderSize(f, 1024*1024)
	count := 0
	for {
		line, err := r.ReadBytes('\n')
		if len(line) > 0 {
			count++
			s.discoverLogLine(bytes.TrimSpace(line))
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return Result{}, err
		}
	}
	return Result{Collector: s.c, Count: count, Warnings: s.warnings}, nil
}

func FTDCFile(path string) (Result, error) {
	s := &Scanner{c: registry.NewCollector()}
	data, err := os.ReadFile(path)
	if err != nil {
		return Result{}, err
	}
	docs, err := ftdc.Iterate(data)
	if err != nil {
		s.warn(err.Error())
	}
	for _, raw := range docs {
		t, ok := ftdc.Type(raw.Doc)
		if !ok {
			continue
		}
		switch t {
		case ftdc.TypeMetadata, ftdc.TypePeriodicMetadata:
			if inner, ok := ftdc.DocField(raw.Doc, "doc"); ok {
				s.deepDiscoverBSON(inner, 0, false)
			}
		case ftdc.TypeMetricChunk:
			bin, ok := ftdc.BinaryField(raw.Doc, "data")
			if !ok {
				continue
			}
			chunk, err := ftdc.DecompressMetricChunk(bin.Data)
			if err != nil {
				s.warn(fmt.Sprintf("chunk decompress failed: %v", err))
				continue
			}
			var ref bson.D
			if err := bson.Unmarshal(chunk.RefBSON, &ref); err != nil {
				s.warn(fmt.Sprintf("reference BSON decode failed: %v", err))
				continue
			}
			s.deepDiscoverBSON(ref, 0, false)
		}
	}
	return Result{Collector: s.c, Count: len(docs), Warnings: s.warnings}, nil
}

func (s *Scanner) warn(msg string)                 { s.warnings = append(s.warnings, msg) }
func (s *Scanner) register(category, value string) { s.c.Register(category, value) }

var reIP = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
var reFQDN = regexp.MustCompile(`\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?\.){2,}[a-zA-Z]{2,}\b`)
var reEmail = regexp.MustCompile(`\b[\w.+-]+@[\w.-]+\.\w{2,}\b`)
var reJavaClass = regexp.MustCompile(`\b((?:[a-z][a-z0-9]*\.){2,}[A-Z]\w*)\b`)
var reBSONStringField = regexp.MustCompile(`(\w+):\s*"([^"]*)"`)
var rePureNumber = regexp.MustCompile(`^-?\d+\.?\d*$`)
var reHex = regexp.MustCompile(`^[0-9a-fA-F]{24,}$`)
var reUUIDLike = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

var hostKeys = set("host", "hostAndPort", "hostName", "syncSource", "syncSourceHost", "syncSourceCandidate", "candidateNode", "candidate", "peer", "newSyncSource", "oldSyncSource", "previousSyncSource", "currentSyncSource", "unsupportedSyncSource", "syncTarget", "remoteHost", "senderHost", "donorHost", "addr", "address", "server", "serverAddress", "serverHost", "endpoint", "localEndpoint", "primary", "newPrimary", "targetPrimary", "node", "failedHost", "sniName", "me")
var remoteLocalKeys = set("remote", "local", "remoteAddr", "remoteSocketAddress", "remoteString", "remoteAddress", "sourceClient")
var namespaceKeys = set("ns", "namespace", "nss", "sourceNss", "targetNss", "newNss", "oldNss", "sourceNamespace", "targetNamespace", "destinationNamespace", "affectedNamespaces")
var databaseKeys = set("database", "db", "dbName", "dbname", "$db", "authenticationDatabase")
var collectionKeys = set("collection", "coll", "collName", "find", "aggregate", "insert", "update", "delete", "findAndModify")
var replsetKeys = set("replSetName", "setName", "replicaSet", "set")
var userKeys = set("user", "userName", "queryUser", "principalName")
var pathKeys = set("dbPath", "path", "filePath", "filepath", "configPath", "logPath", "file", "fileName", "dir", "directory")
var connStringKeys = set("connString", "connectionString", "uri", "mongoUri", "ldapurl")
var shardKeys = set("shard", "shardId", "fromShard", "toShard", "donorShardId", "recipientShardId")
var appNameKeys = set("appName", "clientName")

// X.509 subject and issuer names: replaced whole, they name the organisation,
// unit, location and host.
var certSubjectKeys = set("peerSubject", "peerSubjectName", "subjectName", "issuerName", "subject", "issuer", "certificateSubject", "x509Subject")
var freetextKeys = set("msg", "error", "errmsg", "reason", "message", "info", "errorMessage", "description")
var hostListKeys = set("addresses", "failedHosts", "nodes", "configServers", "listenAddrs", "hosts", "passives", "arbiters")
var skipKeys = set("t", "s", "c", "id", "ctx", "svc", "tags", "connectionId", "durationMillis", "millis", "docsExamined", "keysExamined", "numYields", "nreturned", "txnNumber", "opId", "version", "port", "ok", "code", "codeName", "result", "numDocs", "numRecords", "protocol", "planSummary", "queryHash", "planCacheKey", "type")
var bsonStructuralKeys = set("op", "v", "t", "ts", "wall", "stmtId", "txnNumber", "ui", "lsid", "uid", "_id", "$oid", "$uuid", "$date", "$timestamp", "$binary", "$numberLong", "$numberInt", "$numberDouble", "$regularExpression", "readConcern", "writeConcern", "sort", "projection", "$v", "diff", "u", "i", "d", "$set", "$unset", "$inc", "$push", "$pull", "key", "unique")
var internalDBs = set("admin", "local", "config")

// LDAP distinguished-name components: dc= values name the organisation's
// domain, cn=/uid= values name accounts. ou= values are usually generic
// ("Users", "ServiceAccounts") and are left alone.
var reLDAPComponent = regexp.MustCompile(`(?i)\b(dc|cn|uid|o)=([^,;)\s"'\\{}*%?]+)`)
var commonDCs = set("com", "net", "org", "edu", "gov", "mil", "int", "io", "local", "corp", "example", "internal", "lan")
var knownNonDomains = set("system.version", "system.sessions", "system.profile", "system.views", "$cmd", "startup_log")

func set(values ...string) map[string]struct{} {
	out := map[string]struct{}{}
	for _, v := range values {
		out[v] = struct{}{}
	}
	return out
}
func has(m map[string]struct{}, key string) bool { _, ok := m[key]; return ok }

func (s *Scanner) discoverLogLine(line []byte) {
	if len(line) == 0 {
		return
	}
	prefix, doc, structured := logline.Split(line)
	if structured && len(prefix) > 0 {
		s.discoverFreetext(string(prefix))
		line = doc
	}
	var obj map[string]any
	if err := json.Unmarshal(line, &obj); err == nil {
		s.deepDiscover(obj, 0, false)
		if attr, ok := obj["attr"].(map[string]any); ok {
			for _, key := range []string{"command", "cmdObj", "originatingCommand"} {
				if cmd, ok := attr[key].(map[string]any); ok {
					s.discoverCommandData(cmd, 0)
				}
			}
		}
		return
	}
	s.discoverFreetext(string(line))
}

func (s *Scanner) discoverValue(key string, val any) {
	text, ok := val.(string)
	if !ok || strings.TrimSpace(text) == "" {
		return
	}
	text = strings.TrimSpace(text)
	switch {
	case has(certSubjectKeys, key) && strings.Contains(text, "="):
		s.register("cert_subject", text)
		s.discoverLDAP(text)
	case has(replsetKeys, key):
		s.register("replset", text)
	case has(shardKeys, key):
		s.register("shard", text)
	case has(databaseKeys, key):
		if !has(internalDBs, text) && text != "$external" {
			s.register("database", text)
		}
	case has(collectionKeys, key):
		if !internalCollection(text) {
			s.register("collection", text)
		}
	case has(namespaceKeys, key):
		s.discoverNamespace(text)
	case has(userKeys, key):
		if strings.Contains(text, "@") {
			s.register("email", text)
			if parts := strings.SplitN(text, "@", 2); len(parts) == 2 {
				s.register("domain", parts[1])
			}
		} else if !has(internalUsers, text) {
			s.register("user", text)
		}
	case has(pathKeys, key):
		if strings.HasPrefix(text, "/") {
			s.register("path", text)
		}
	case has(hostKeys, key) || has(remoteLocalKeys, key):
		s.discoverHostValue(text)
	case has(connStringKeys, key):
		s.discoverConnString(text)
	case has(appNameKeys, key):
		if !toolAppName(text) {
			s.register("appname", text)
		}
	case has(hostListKeys, key):
		for _, part := range splitListish(text) {
			s.discoverHostValue(part)
		}
	case has(freetextKeys, key):
		s.discoverFreetext(text)
		s.discoverBSONDocument(text)
	default:
		s.discoverFreetextLight(text)
	}
}

// categorizedKey reports keys whose values have a known category.
func categorizedKey(key string) bool {
	for _, keys := range []map[string]struct{}{replsetKeys, shardKeys, databaseKeys, collectionKeys, namespaceKeys, userKeys, pathKeys, hostKeys, remoteLocalKeys, connStringKeys, appNameKeys, hostListKeys, certSubjectKeys} {
		if has(keys, key) {
			return true
		}
	}
	return false
}

// Collections created by MongoDB itself and by Percona Backup for MongoDB
// keep their names: they say what the server or the backup tool was doing.
var internalCollections = set("oplog.rs", "transactions", "image_collection", "startup_log", "me", "replset.election", "replset.minvalid", "replset.oplogTruncateAfterPoint", "replset.initialSyncId", "chunks", "collections", "databases", "shards", "mongos", "locks", "lockpings", "settings", "version", "tags", "changelog", "actionlog", "migrations", "migrationCoordinators", "rangeDeletions", "reshardingOperations", "tenantMigrationDonors", "tenantMigrationRecipients", "clusterParameters", "placementHistory", "queryAnalyzers", "sampledQueries", "sampledQueriesDiff", "analyzeShardKeySplitPoints", "vectorClock", "external_validation_keys", "compactStructuredEncryptionData")

func internalCollection(name string) bool {
	if strings.HasPrefix(name, "system.") || strings.HasPrefix(name, "$") || strings.HasPrefix(name, "cache.") {
		return true
	}
	if strings.HasPrefix(name, "pbm") && len(name) > 3 && name[3] >= 'A' && name[3] <= 'Z' {
		return true // pbmBackups, pbmLock, pbmPITRChunks, ...
	}
	return has(internalCollections, name)
}

// Application names of MongoDB, Percona and common client tools keep their
// names: they tell backups, monitoring and shells apart from the application.
var toolAppNames = set("OplogFetcher", "pbm", "pbm-agent", "pbm-speed-test", "mongodb_exporter", "pmm-agent", "mongodump", "mongorestore", "mongoexport", "mongoimport", "mongostat", "mongotop", "mongofiles", "mongosync", "mongomirror", "Studio 3T", "NoSQLBooster", "MongoDB Compass", "MongoDB Automation Agent", "MongoDB Monitoring Module", "MongoDB Backup Agent", "MongoDB CPS Module", "MongoDB Shell", "MongoDB Internal Client")

func toolAppName(name string) bool {
	return has(toolAppNames, name) || strings.HasPrefix(name, "mongosh") || strings.HasPrefix(name, "MongoDB ") || strings.HasPrefix(name, "pbm") || strings.HasPrefix(name, "Percona ")
}

// Users created by the server itself.
var internalUsers = set("__system", "__queryable_backup")

func splitListish(s string) []string {
	s = strings.NewReplacer("[", "", "]", "").Replace(s)
	parts := strings.Split(s, ",")
	out := []string{}
	for _, p := range parts {
		p = strings.Trim(strings.TrimSpace(p), `"'`)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func (s *Scanner) discoverNamespace(ns string) {
	if has(knownNonDomains, ns) {
		return
	}
	parts := strings.SplitN(ns, ".", 2)
	if len(parts) != 2 {
		return
	}
	if has(internalDBs, parts[0]) {
		return // admin, local and config collections are MongoDB's or tools'
	}
	s.register("database", parts[0])
	if !internalCollection(parts[1]) {
		s.register("collection", parts[1])
	}
}

// notHosts are values that host fields hold when there is no host.
var notHosts = set("unknown", "empty", "none", "null", "nil", "n/a", "localhost", "(none)", "self")

func (s *Scanner) discoverHostValue(val string) {
	if strings.HasPrefix(val, "/") {
		// a Unix socket path, not a host
		if !strings.HasPrefix(val, "/tmp/") && !strings.HasPrefix(val, "/var/run/") && !strings.HasPrefix(val, "/run/") {
			s.register("path", val)
		}
		return
	}
	if strings.ContainsAny(val, " \t") || has(notHosts, strings.ToLower(val)) {
		return
	}
	host := val
	if strings.Contains(val, ":") && !strings.HasPrefix(val, "[") {
		if idx := strings.LastIndex(val, ":"); idx >= 0 {
			host = val[:idx]
		}
	}
	if reIP.MatchString(host) && reIP.FindString(host) == host {
		if !strings.HasPrefix(host, "127.") && host != "0.0.0.0" {
			s.register("ip", host)
		}
		return
	}
	if strings.Contains(host, ".") {
		s.register("fqdn", host)
		parts := strings.Split(host, ".")
		if len(parts) >= 3 {
			s.register("domain", strings.Join(parts[len(parts)-2:], "."))
		}
		s.register("hostname", parts[0])
		return
	}
	s.register("hostname", host)
}
func (s *Scanner) discoverConnString(val string) {
	re := regexp.MustCompile(`mongodb(?:\+srv)?://(.+?)(?:/(.*))?$`)
	if m := re.FindStringSubmatch(val); m != nil {
		for _, hp := range strings.Split(m[1], ",") {
			s.discoverHostValue(strings.TrimSpace(hp))
		}
		if len(m) > 2 {
			db := strings.SplitN(m[2], "?", 2)[0]
			if db != "" && !has(internalDBs, db) {
				s.register("database", db)
			}
		}
		return
	}
}
func (s *Scanner) discoverFreetext(text string) {
	for _, email := range reEmail.FindAllString(text, -1) {
		s.register("email", email)
		if parts := strings.SplitN(email, "@", 2); len(parts) == 2 {
			s.register("domain", parts[1])
		}
	}
	for _, ip := range reIP.FindAllString(text, -1) {
		if !strings.HasPrefix(ip, "127.") && ip != "0.0.0.0" {
			s.register("ip", ip)
		}
	}
	for _, fqdn := range reFQDN.FindAllString(text, -1) {
		if strings.HasSuffix(fqdn, ".mongodb.org") || strings.HasSuffix(fqdn, ".example.com") || has(knownNonDomains, fqdn) || !plausibleHostName(fqdn) {
			continue
		}
		parts := strings.Split(fqdn, ".")
		if has(internalDBs, parts[0]) || len(parts) > 4 {
			continue
		}
		s.register("fqdn", fqdn)
		if len(parts) >= 3 {
			s.register("domain", strings.Join(parts[len(parts)-2:], "."))
		}
		s.register("hostname", parts[0])
	}
	for _, cls := range reJavaClass.FindAllString(text, -1) {
		if !publicJavaPackage(cls) {
			s.register("java_class", cls)
		}
	}
	s.discoverLDAP(text)
}

// Packages of the JDK, the MongoDB drivers and common frameworks: their class
// names in stack traces are not the customer's.
var publicJavaPackages = []string{"java.", "javax.", "jdk.", "sun.", "com.sun.", "kotlin.", "kotlinx.", "scala.", "org.springframework.", "org.mongodb.", "com.mongodb.", "org.bson.", "org.apache.", "io.netty.", "reactor.", "io.micrometer.", "org.hibernate.", "com.fasterxml.", "org.slf4j.", "ch.qos.", "io.grpc.", "com.google.", "org.junit.", "io.vertx.", "io.quarkus."}

func publicJavaPackage(class string) bool {
	for _, p := range publicJavaPackages {
		if strings.HasPrefix(class, p) {
			return true
		}
	}
	return false
}

// discoverLDAP registers the organisation (dc=) and account (cn=, uid=)
// names of LDAP distinguished names and queries in free text.
func (s *Scanner) discoverLDAP(text string) {
	if !strings.Contains(text, "=") {
		return
	}
	for _, m := range reLDAPComponent.FindAllStringSubmatch(text, -1) {
		attr, value := strings.ToLower(m[1]), m[2]
		if len(value) < 2 {
			continue
		}
		if attr == "dc" || attr == "o" {
			if !has(commonDCs, strings.ToLower(value)) {
				s.register("org", value)
			}
			continue
		}
		s.register("user", value)
	}
}

func hasLDAPComponent(text string) bool {
	lower := strings.ToLower(text)
	return strings.Contains(lower, "dc=") || strings.Contains(lower, "cn=") || strings.Contains(lower, "uid=") || strings.Contains(lower, "o=")
}

// discoverKey registers host:port and path keys, as used by topology
// descriptions, connection pools and listener socket statistics.
func (s *Scanner) discoverKey(key string) {
	switch {
	case strings.HasPrefix(key, "/"):
		if !strings.HasPrefix(key, "/tmp/") && !strings.HasPrefix(key, "/var/run/") && !strings.HasPrefix(key, "/run/") {
			s.register("path", key)
		}
	case strings.Contains(key, ":"):
		i := strings.LastIndex(key, ":")
		port := key[i+1:]
		if port != "" && strings.Trim(port, "0123456789") == "" && i > 0 {
			s.discoverHostValue(key)
		}
	}
}

// Top-level domains accepted for host names found in free text. Free text
// also holds Java class names (java.util.concurrent.ThreadPoolExecutor),
// versions (4.1.13.final) and build hosts; host fields are trusted as is.
var hostTLDs = set("com", "net", "org", "edu", "gov", "mil", "int", "io", "co", "biz", "info", "local", "internal", "corp", "lan", "intra", "intranet", "cloud", "app", "dev", "ai", "me", "tech", "online", "site", "xyz", "group", "bank", "finance", "insurance", "health", "global", "eu", "us", "uk", "de", "fr", "es", "it", "nl", "be", "ch", "at", "se", "no", "dk", "fi", "pl", "pt", "ie", "ca", "au", "nz", "jp", "cn", "in", "br", "mx", "ar", "cl", "za", "sg", "hk", "tw", "kr", "ru", "il", "ae", "sa", "tr", "id", "my", "th", "vn", "ph", "lu", "cz", "gr", "ro", "hu")

// Public vendor domains that appear in build and version strings.
var vendorDomains = []string{"redhat.com", "mongodb.com", "mongodb.org", "percona.com", "ubuntu.com", "debian.org", "centos.org", "fedoraproject.org", "github.com", "golang.org", "openssl.org"}

func plausibleHostName(name string) bool {
	if strings.ToLower(name) != name {
		return false
	}
	labels := strings.Split(name, ".")
	if !has(hostTLDs, labels[len(labels)-1]) {
		return false
	}
	for _, d := range vendorDomains {
		if name == d || strings.HasSuffix(name, "."+d) {
			return false
		}
	}
	return true
}

func (s *Scanner) discoverFreetextLight(text string) {
	if reIP.MatchString(text) || reEmail.MatchString(text) || reFQDN.MatchString(text) || hasLDAPComponent(text) {
		s.discoverFreetext(text)
	}
}
func (s *Scanner) isSafeBSONValue(key, value string) bool {
	return value == "" || len(value) < 2 || has(bsonStructuralKeys, key) || rePureNumber.MatchString(value) || reHex.MatchString(value) || reUUIDLike.MatchString(value) || len(value) == 1
}
func (s *Scanner) discoverBSONDocument(text string) {
	if !strings.Contains(text, `: "`) && !strings.Contains(text, `": "`) {
		return
	}
	for _, m := range reBSONStringField.FindAllStringSubmatch(text, -1) {
		key, value := m[1], m[2]
		if s.isSafeBSONValue(key, value) {
			continue
		}
		if categorizedKey(key) {
			// "setName: \"rs0\"" in an error message is the same replica
			// set name as "setName":"rs0" in JSON.
			s.discoverValue(key, value)
			continue
		}
		switch {
		case key == "ns" || (key == "namespace" && strings.Contains(value, ".")):
			s.discoverNamespace(value)
		case strings.Contains(value, "@") && reEmail.MatchString(value):
			s.register("email", value)
		case reIP.MatchString(value) && reIP.FindString(value) == value:
			s.register("ip", value)
		case strings.HasPrefix(value, "/"):
			s.register("path", value)
		case reFQDN.MatchString(value) && reFQDN.FindString(value) == value:
			s.discoverHostValue(value)
		default:
			s.register("data", value)
		}
	}
}

func (s *Scanner) deepDiscover(obj any, depth int, inCommand bool) {
	if depth > 20 {
		return
	}
	switch v := obj.(type) {
	case map[string]any:
		for key, val := range v {
			if strings.ContainsAny(key, ":/") {
				s.discoverKey(key)
			}
			if has(skipKeys, key) || redact.DocumentContainer(key) {
				continue
			}
			child := inCommand || redact.CommandContext(key)
			if child && key == "pipeline" {
				s.discoverPipeline(val)
			}
			if redact.PayloadField(key, val, child) {
				continue
			}
			if _, isString := val.(string); isString && child && !redact.CommandSafeString(key) {
				continue
			}
			s.discoverValue(key, val)
			switch val.(type) {
			case map[string]any, []any:
				s.deepDiscover(val, depth+1, child)
			}
		}
	case []any:
		for _, item := range v {
			s.deepDiscover(item, depth+1, inCommand)
		}
	case string:
		if !inCommand {
			s.discoverFreetextLight(v)
		}
	}
}

// discoverPipeline registers the collections an aggregation pipeline reads
// or writes: $lookup/$graphLookup from, $unionWith, $out, $merge into, at any
// depth ($facet, sub-pipelines). Pipelines are otherwise payload.
func (s *Scanner) discoverPipeline(v any) {
	stages, ok := v.([]any)
	if !ok {
		return
	}
	for _, stage := range stages {
		obj, ok := stage.(map[string]any)
		if !ok {
			continue
		}
		for op, spec := range obj {
			switch op {
			case "$out", "$unionWith", "$merge", "$lookup", "$graphLookup":
				if name, ok := spec.(string); ok {
					s.registerCollection(name)
					continue
				}
				if m, ok := spec.(map[string]any); ok {
					s.discoverStageSpec(m)
				}
			case "$facet":
				if m, ok := spec.(map[string]any); ok {
					for _, sub := range m {
						s.discoverPipeline(sub)
					}
				}
			}
		}
	}
}

func (s *Scanner) discoverStageSpec(spec map[string]any) {
	for key, val := range spec {
		switch key {
		case "from", "coll":
			if name, ok := val.(string); ok {
				s.registerCollection(name)
			}
		case "into":
			switch x := val.(type) {
			case string:
				s.registerCollection(x)
			case map[string]any:
				s.discoverStageSpec(x)
			}
		case "db":
			if name, ok := val.(string); ok && !has(internalDBs, name) {
				s.register("database", name)
			}
		case "pipeline":
			s.discoverPipeline(val)
		}
	}
}

func (s *Scanner) registerCollection(name string) {
	if !internalCollection(name) {
		s.register("collection", name)
	}
}

// internalCommandDB reports a command run against admin, local or config.
func internalCommandDB(cmd map[string]any) bool {
	db, _ := cmd["$db"].(string)
	return has(internalDBs, db)
}

func (s *Scanner) discoverCommandData(obj any, depth int) {
	if depth > 10 {
		return
	}
	switch v := obj.(type) {
	case map[string]any:
		for _, key := range []string{"find", "aggregate", "insert", "update", "delete", "findAndModify", "count", "distinct", "getMore", "create", "drop", "renameCollection", "createIndexes", "dropIndexes", "collMod", "explain"} {
			if coll, ok := v[key].(string); ok && !internalCollection(coll) && !internalCommandDB(v) {
				s.register("collection", coll)
			}
		}
		if to, ok := v["to"].(string); ok && strings.Contains(to, ".") {
			s.discoverNamespace(to)
		}
		for key, val := range v {
			if key == "pipeline" {
				s.discoverPipeline(val)
			}
			if redact.PayloadField(key, val, true) || redact.DocumentContainer(key) {
				continue
			}
			switch val.(type) {
			case map[string]any, []any:
				s.discoverCommandData(val, depth+1)
			}
		}
	case []any:
		for _, item := range v {
			s.discoverCommandData(item, depth+1)
		}
	}
}
func (s *Scanner) deepDiscoverBSON(doc bson.D, depth int, inCommand bool) {
	if depth > 20 {
		return
	}
	for _, elem := range doc {
		if strings.ContainsAny(elem.Key, ":/") {
			s.discoverKey(elem.Key)
		}
		if has(skipKeys, elem.Key) || redact.DocumentContainer(elem.Key) {
			continue
		}
		child := inCommand || redact.CommandContext(elem.Key)
		if redact.PayloadField(elem.Key, elem.Value, child) {
			continue
		}
		switch v := elem.Value.(type) {
		case string:
			if child && !redact.CommandSafeString(elem.Key) {
				continue
			}
			s.discoverValue(elem.Key, v)
		case bson.D:
			s.deepDiscoverBSON(v, depth+1, child)
		case bson.A:
			s.discoverBSONList(elem.Key, v, depth+1, child)
		}
	}
}
func (s *Scanner) discoverBSONList(parentKey string, arr bson.A, depth int, inCommand bool) {
	if depth > 20 {
		return
	}
	if has(hostListKeys, parentKey) {
		for _, item := range arr {
			if v, ok := item.(string); ok {
				s.discoverHostValue(v)
			}
		}
		return
	}
	for _, item := range arr {
		switch v := item.(type) {
		case bson.D:
			s.deepDiscoverBSON(v, depth, inCommand)
		case string:
			if !inCommand {
				s.discoverFreetextLight(v)
			}
		case bson.A:
			s.discoverBSONList(parentKey, v, depth+1, inCommand)
		}
	}
}
