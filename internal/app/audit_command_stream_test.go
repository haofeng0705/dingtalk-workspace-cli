// Copyright 2026 Alibaba Group
// SPDX-License-Identifier: Apache-2.0

package app

import (
	"encoding/csv"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/DingTalk-Real-AI/dingtalk-workspace-cli/internal/audit"
	apperrors "github.com/DingTalk-Real-AI/dingtalk-workspace-cli/internal/errors"
)

func TestCrossPlatformCoverageAuditStreamCommands(t *testing.T) {
	configDir := t.TempDir()
	t.Setenv("DWS_CONFIG_DIR", configDir)
	t.Setenv("DWS_KEYCHAIN_DIR", t.TempDir())
	t.Setenv(audit.EnvAuditDir, t.TempDir())
	t.Setenv(audit.EnvAudit, "1")
	t.Setenv(audit.EnvForwardURL, "")

	toolSink, err := audit.BuildSink(configDir, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := toolSink.Emit(&audit.Event{Timestamp: time.Now(), ExecutionID: "tool-record"}); err != nil {
		t.Fatal(err)
	}
	if err := toolSink.Close(); err != nil {
		t.Fatal(err)
	}
	command := audit.CommandEvent{
		Timestamp: time.Now(), CommandID: "command-record", CommandPath: "calendar/event/delete",
		Surface: "execute", Result: "failure", ExitCode: 3, ErrReason: "command_denied",
		Policy: &audit.CommandPolicy{
			State: "active", Decision: "deny", TargetPath: "calendar/event/delete",
			RuleName: "calendar-readonly", ReasonCode: "risk_too_high",
		},
	}
	if err := audit.WriteCommand(configDir, &command); err != nil {
		t.Fatal(err)
	}
	query := func(args ...string) string {
		t.Helper()
		out, err := executePolicyRoot(t, append([]string{"audit"}, args...)...)
		if err != nil {
			t.Fatalf("audit %v: %v\n%s", args, err, out)
		}
		return out
	}
	for _, sub := range []string{"tail", "export"} {
		out := query(sub, "--stream", "command")
		var event audit.CommandEvent
		if err := json.Unmarshal([]byte(out), &event); err != nil || event.CommandID != command.CommandID || event.Policy == nil || event.Policy.RuleName != command.Policy.RuleName {
			t.Fatalf("%s command stream: %v\n%s", sub, err, out)
		}
		tool := query(sub)
		if tool != query(sub, "--stream", "tool") || !strings.Contains(tool, "tool-record") || strings.Contains(tool, "command-record") {
			t.Fatalf("%s default tool stream: %s", sub, tool)
		}
	}

	rows, err := csv.NewReader(strings.NewReader(query("export", "--stream", "command", "--format", "csv"))).ReadAll()
	if err != nil || len(rows) != 2 {
		t.Fatalf("command csv: rows=%v err=%v", rows, err)
	}
	for name, want := range map[string]string{
		"command_id": "command-record", "exit_code": "3", "policy_decision": "deny",
		"policy_rule_name": "calendar-readonly", "policy_reason_code": "risk_too_high", "tool_execution_ids": "[]",
	} {
		if col := slices.Index(rows[0], name); col < 0 || rows[1][col] != want {
			t.Errorf("csv %s: want %q, got rows %v", name, want, rows)
		}
	}
	commandFile, err := audit.LatestAuditFile(audit.CommandDir(configDir))
	if err != nil {
		t.Fatal(err)
	}
	toolFile, err := audit.LatestAuditFile(audit.Dir(configDir))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		args []string
		file string
	}{
		{[]string{"--stream", "command"}, commandFile},
		{nil, toolFile},
		{[]string{"--file", commandFile}, commandFile},
		{[]string{"--file", toolFile, "--stream", "command"}, toolFile},
	} {
		out := query(append([]string{"verify", "--format", "json"}, tc.args...)...)
		var verification struct {
			Valid bool
			File  string
		}
		if err := json.Unmarshal([]byte(out), &verification); err != nil || !verification.Valid || verification.File != tc.file {
			t.Errorf("verify %v: %v\n%s", tc.args, err, out)
		}
	}
}

func TestCrossPlatformCoverageAuditStreamReadErrors(t *testing.T) {
	configDir := t.TempDir()
	t.Setenv("DWS_CONFIG_DIR", configDir)
	t.Setenv("DWS_KEYCHAIN_DIR", t.TempDir())
	t.Setenv(audit.EnvAuditDir, t.TempDir())
	t.Setenv(audit.EnvAudit, "1")
	if err := audit.WriteCommand(configDir, &audit.CommandEvent{
		CommandID: "early-failure", Surface: "unresolved", Result: "failure", ExitCode: 3,
	}); err != nil {
		t.Fatal(err)
	}
	out, err := executePolicyRoot(t, "audit", "export", "--stream", "command", "--format", "csv")
	if err != nil || !strings.Contains(out, "early-failure") {
		t.Fatalf("command without policy snapshot: %v\n%s", err, out)
	}
	reader, closedOutput := io.Pipe()
	reader.Close()
	defer closedOutput.Close()
	for _, sub := range []string{"tail", "export", "verify"} {
		root := NewRootCommand()
		root.SetOut(closedOutput)
		root.SetErr(io.Discard)
		args := []string{"audit", sub, "--stream", "command"}
		if sub == "verify" {
			args = append(args, "--format", "json")
		}
		root.SetArgs(args)
		if err := root.Execute(); !errors.Is(err, io.ErrClosedPipe) {
			t.Errorf("audit %s failed writer: %v", sub, err)
		}
	}
	if _, err := executePolicyRoot(t, "audit", "verify", "--format", "json", "--file", filepath.Join(configDir, "missing")); err == nil {
		t.Fatal("missing explicit verify file reported as valid")
	}
	for _, stream := range []string{"command", "tool"} {
		dir, err := auditStreamDir(stream)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "audit-20010102.jsonl"), []byte("\n{\n"), 0600); err != nil {
			t.Fatal(err)
		}
		_, err = executePolicyRoot(t, "audit", "export", "--stream", stream, "--format", "csv")
		if err == nil || !strings.Contains(err.Error(), "audit-20010102.jsonl:2") {
			t.Errorf("%s malformed CSV source: %v", stream, err)
		}
	}
}

func TestCrossPlatformCoverageAuditStreamContract(t *testing.T) {
	for _, sub := range []string{"tail", "export", "verify"} {
		if _, err := executePolicyRoot(t, "audit", sub, "--stream", "../commands"); apperrors.ExitCode(err) != 3 {
			t.Errorf("audit %s accepted invalid --stream or returned wrong error: %v", sub, err)
		}
		out, err := executePolicyRoot(t, "audit", sub, "--help")
		if err != nil || !strings.Contains(out, "--stream") {
			t.Fatalf("audit %s --help missing stream: %v\n%s", sub, err, out)
		}
		leaf := schemaJSON(t, "audit."+sub, "-f", "json")
		assertSchemaLeafParameterEnum(t, leaf, "audit "+sub, "stream", []string{"tool", "command"})
		param := schemaContractMap(leaf["parameters"])["stream"]
		if param["default"] != "tool" {
			t.Errorf("audit %s stream default: %v", sub, param["default"])
		}
	}
}
