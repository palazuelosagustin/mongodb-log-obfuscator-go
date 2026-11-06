package main

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// Every flag of the usage text is documented in the README and the skill
// names the binary and its exit statuses.
func TestREADMEAndSkillMatchCLI(t *testing.T) {
	readme, err := os.ReadFile("../../README.md")
	if err != nil {
		t.Fatal(err)
	}
	for _, flag := range regexp.MustCompile(`--[a-z][a-z-]+`).FindAllString(usageText, -1) {
		if !strings.Contains(string(readme), "`"+flag) {
			t.Errorf("README does not document %s", flag)
		}
	}
	skill, err := os.ReadFile("../../skills/.claude/mongodb-log-obfuscator-go/SKILL.md")
	if err != nil {
		t.Fatal(err)
	}
	codex, err := os.ReadFile("../../skills/.codex/mongodb-log-obfuscator-go/SKILL.md")
	if err != nil {
		t.Fatal(err)
	}
	if string(codex) != string(skill) {
		t.Errorf("the Codex skill differs from the Claude skill")
	}
	for _, want := range []string{"mongodb-log-obfuscator-go --verify", "verify [--mapping FILE] OUTPUT_DIR", "| 3 |", "--keep-equality", "--load-mapping", "--from", "--dry-run"} {
		if !strings.Contains(string(skill), want) {
			t.Errorf("skill does not mention %q", want)
		}
	}
}
