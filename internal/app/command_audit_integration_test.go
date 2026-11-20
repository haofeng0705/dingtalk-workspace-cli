// Copyright 2026 Alibaba Group
// SPDX-License-Identifier: Apache-2.0

package app

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DingTalk-Real-AI/dingtalk-workspace-cli/internal/testseam"
	"github.com/DingTalk-Real-AI/dingtalk-workspace-cli/pkg/edition"
)

func TestCrossPlatformCoverageCommandAuditOutcomes(t *testing.T) {
	restrictForTest(t, staticRules(edition.CommandRule{Name: "calendar-readonly", Allow: []string{"calendar/**"}, MaxEffect: edition.EffectRead}))
	for _, tc := range []struct {
		name, surface, path, target, decision, reason string
		args                                          []string
		code                                          int
	}{
		{"refused execution", "execute", "calendar/event/delete", "calendar/event/delete", "deny", "risk_too_high", []string{"calendar", "event", "delete"}, 3},
		{"ordinary validation", "execute", "calendar/event/list", "calendar/event/list", "allow", "", []string{"calendar", "event", "list", "--no-such-flag"}, 3},
		{"help refusal", "help", "help", "calendar/event/delete", "deny", "risk_too_high", []string{"help", "calendar", "event", "delete"}, 3},
		{"schema refusal", "schema", "schema", "calendar/event/delete", "deny", "risk_too_high", []string{"schema", "--cli-path", "calendar event delete"}, 3},
		{"group help exit zero", "help", "report", "report", "deny", "all_children_denied", []string{"report", "--help"}, 0},
		{"inspect policy", "policy_inspect", "config/policy/show", "config/policy/show", "allow", "", []string{"config", "policy", "show"}, 0},
		{"ordinary help", "", "", "", "", "", []string{"calendar", "event", "list", "--help"}, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			t.Setenv("DWS_AUDIT", "1")
			t.Setenv("DWS_AUDIT_DIR", dir)
			testseam.Swap(t, &os.Args, append([]string{"dws"}, tc.args...))
			code, _, _ := ExecuteWithTelemetry()
			if code != tc.code {
				t.Fatalf("exit %d, want %d", code, tc.code)
			}
			files, err := filepath.Glob(filepath.Join(dir, "commands", "*.jsonl"))
			if err != nil {
				t.Fatal(err)
			}
			if tc.surface == "" {
				if len(files) != 0 {
					t.Fatalf("unexpected audit file: %v", files)
				}
				return
			}
			if len(files) != 1 {
				t.Fatalf("got %d command files, want one", len(files))
			}
			data, err := os.ReadFile(files[0])
			if err != nil {
				t.Fatal(err)
			}
			var event struct {
				CommandID   string `json:"command_id"`
				CommandPath string `json:"command_path"`
				Surface     string `json:"surface"`
				ExitCode    *int   `json:"exit_code"`
				Policy      struct {
					State, Decision string
					Target          string `json:"target_path"`
					Reason          string `json:"reason_code"`
				} `json:"policy"`
			}
			if err = json.Unmarshal(data, &event); err != nil {
				t.Fatalf("expected one JSON record: %v", err)
			}
			if event.CommandID == "" || event.Surface != tc.surface || event.CommandPath != tc.path || event.ExitCode == nil || *event.ExitCode != tc.code || event.Policy.State != "active" || event.Policy.Decision != tc.decision || event.Policy.Target != tc.target || event.Policy.Reason != tc.reason {
				t.Errorf("unexpected event %s", data)
			}
			if strings.Contains(string(data), "--no-such-flag") {
				t.Error("command audit includes argv")
			}
		})
	}
}
