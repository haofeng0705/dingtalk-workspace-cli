// Copyright 2026 Alibaba Group
// SPDX-License-Identifier: Apache-2.0

package app

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/DingTalk-Real-AI/dingtalk-workspace-cli/internal/audit"
	"github.com/DingTalk-Real-AI/dingtalk-workspace-cli/internal/cmdpolicy"
	apperrors "github.com/DingTalk-Real-AI/dingtalk-workspace-cli/internal/errors"
	"github.com/DingTalk-Real-AI/dingtalk-workspace-cli/internal/testseam"
	"github.com/DingTalk-Real-AI/dingtalk-workspace-cli/pkg/edition"
)

func TestCrossPlatformCoverageCommandAuditPolicyMatrix(t *testing.T) {
	const (
		rawGuidance = "audit-test-private-distributor-guidance"
		badFlag     = "--audit-test-private-argument"
		readPath    = "calendar/event/list"
	)
	denyReports := edition.CommandRule{
		Name: "no-submit", Allow: []string{"report/**"}, Deny: []string{"report/entry/submit"},
		AllowUnannotated: true, DenyMessage: rawGuidance,
	}
	statusOnly := staticRules(edition.CommandRule{Name: "status", Allow: []string{"dingtalk-tag/connect/status"}, AllowUnannotated: true})
	cases := []struct {
		name                  string
		policy                func() []edition.CommandRule
		args                  []string
		path, state, decision string
		reason, rule          string
	}{
		{"disabled", nil, []string{"calendar", "event", "list", badFlag}, readPath, "disabled", "not_evaluated", "", ""},
		{"empty rules", staticRules(), []string{"calendar", "event", "list"}, readPath, "active", "deny", cmdpolicy.ReasonNoMatchingRule, ""},
		{"invalid", staticRules(edition.CommandRule{Name: "bad", MaxRisk: "invalid"}), []string{"calendar", "event", "list"}, readPath, "invalid", "deny", cmdpolicy.ReasonPolicyInvalid, ""},
		{"unnamed API channel", staticRules(edition.CommandRule{Name: "all", Allow: []string{"**"}, AllowUnannotated: true}), []string{"api", badFlag}, "api", "active", "deny", cmdpolicy.ReasonChannelNotAllowed, ""},
		{"hybrid operation", statusOnly, []string{"dingtalk-tag", "connect"}, "dingtalk-tag/connect", "active", "deny", cmdpolicy.ReasonNotAllowed, "status"},
		{"allowed hybrid child rejects invalid flag", statusOnly, []string{"dingtalk-tag", "connect", "status", badFlag}, "dingtalk-tag/connect/status", "active", "allow", "", "status"},
		{"native alias", staticRules(denyReports), []string{"log", "entry", "submit"}, "report/entry/submit", "active", "deny", cmdpolicy.ReasonDenylisted, "no-submit"},
		{"compatibility alias", staticRules(denyReports), []string{"report", "create"}, "report/create", "active", "deny", cmdpolicy.ReasonDenylisted, "no-submit"},
		{"multiple denials", staticRules(denyReports, edition.CommandRule{Name: "calendar", Allow: []string{"calendar/**"}}), []string{"report", "create"}, "report/create", "active", "deny", cmdpolicy.ReasonNoMatchingRule, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			restrictForTest(t, tc.policy)
			dir := t.TempDir()
			t.Setenv("DWS_AUDIT", "1")
			t.Setenv("DWS_AUDIT_DIR", dir)
			t.Setenv("DWS_CONFIG_DIR", t.TempDir())
			t.Setenv("DWS_KEYCHAIN_DIR", t.TempDir())
			testseam.Swap(t, &os.Args, append([]string{"dws"}, tc.args...))
			code, _, _ := ExecuteWithTelemetry()
			if code != 3 {
				t.Fatalf("exit = %d, want 3", code)
			}
			file, err := audit.LatestAuditFile(filepath.Join(dir, "commands"))
			if err != nil {
				t.Fatal(err)
			}
			raw, err := os.ReadFile(file)
			if err != nil {
				t.Fatal(err)
			}
			var event audit.CommandEvent
			if err := json.Unmarshal(raw, &event); err != nil {
				t.Fatalf("expected one command record: %v", err)
			}
			if bytes.Contains(raw, []byte(rawGuidance)) || bytes.Contains(raw, []byte(badFlag)) {
				t.Fatal("command event includes raw rule guidance or argv")
			}
			if event.CommandPath != tc.path || event.Surface != "execute" || event.ExitCode != code || event.Result != "failure" || len(event.ToolExecutionIDs) != 0 {
				t.Fatalf("unexpected command result: %+v", event)
			}
			p := event.Policy
			if p == nil || p.State != tc.state || p.Decision != tc.decision || p.ReasonCode != tc.reason || p.RuleName != tc.rule {
				t.Fatalf("unexpected policy verdict: %+v", p)
			}
			snapshot := cmdpolicy.Resolve(edition.Get())
			if p.Source != snapshot.Source() || p.ViewHash != snapshot.ViewHash() || (p.ViewHash != "") != (tc.state == "active") {
				t.Fatalf("unexpected policy attribution: %+v", p)
			}
			if (tc.state == "disabled" && p.TargetPath != "") || (tc.state != "disabled" && p.TargetPath != tc.path) {
				t.Fatalf("unexpected target: %+v", p)
			}
			if (event.ErrReason == "command_denied") != (p.Decision == "deny") || (tc.rule == "" && bytes.Contains(raw, []byte(`"rule_name"`))) {
				t.Fatalf("incorrect refusal or invented rule: %+v", event)
			}
		})
	}
}

func isolateCommandAuditForTest(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv(audit.EnvAuditDir, dir)
	t.Setenv(audit.EnvAudit, "1")
	return dir
}

func assertCommandAuditFailure(t *testing.T, dir string, code int, category, reason string) {
	t.Helper()
	file, err := audit.LatestAuditFile(filepath.Join(dir, "commands"))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	var event audit.CommandEvent
	if err := json.Unmarshal(raw, &event); err != nil {
		t.Fatalf("expected one command event: %v", err)
	}
	if event.Result != "failure" || event.ExitCode != code || event.ErrCategory != category || event.ErrReason != reason {
		t.Fatalf("audit result %q/%d %s/%s, want failure/%d %s/%s", event.Result, event.ExitCode, event.ErrCategory, event.ErrReason, code, category, reason)
	}
}

func TestCrossPlatformCoverageCommandAuditWriteFailurePreservesExitCode(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "regular-file")
	if err := os.WriteFile(file, []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(audit.EnvAuditDir, file)
	t.Setenv(audit.EnvAudit, "1")
	t.Setenv(audit.EnvAuditDebug, "1")
	restrictForTest(t, nil)
	for _, tc := range []struct {
		args []string
		code int
	}{
		{[]string{"config", "policy", "show", "--format", "json"}, 0},
		{[]string{"calendar", "event", "list", "--invalid-test-flag"}, 3},
	} {
		t.Run(tc.args[0], func(t *testing.T) {
			diagnostics, err := os.CreateTemp(dir, "stderr-")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = diagnostics.Close() })
			testseam.Swap(t, &os.Stderr, diagnostics)
			testseam.Swap(t, &os.Args, append([]string{"dws"}, tc.args...))
			if code, _, _ := ExecuteWithTelemetry(); code != tc.code {
				t.Fatalf("exit = %d, want %d", code, tc.code)
			}
			raw, err := os.ReadFile(diagnostics.Name())
			if err != nil || !bytes.Contains(raw, []byte("write command event failed")) {
				t.Fatalf("expected audit write failure diagnostic, got: %s, err=%v", raw, err)
			}
		})
	}
}

func TestCrossPlatformCoverageCommandAuditDisabledSkipsProcessWrite(t *testing.T) {
	dir := isolateCommandAuditForTest(t)
	t.Setenv(audit.EnvAudit, "0")
	restrictForTest(t, staticRules())
	testseam.Swap(t, &os.Args, []string{"dws", "calendar", "event", "list"})
	if code, _, _ := ExecuteWithTelemetry(); code != 3 {
		t.Fatalf("disabled audit changed policy refusal exit to %d", code)
	}
	if _, err := os.Stat(filepath.Join(dir, "commands")); !os.IsNotExist(err) {
		t.Fatalf("disabled command audit created a stream: %v", err)
	}
}

func TestCrossPlatformCoverageCommandAuditLocalSurfaceSelection(t *testing.T) {
	root := NewRootCommand()
	unknown := apperrors.MarkUnknownInvocation(errors.New("unknown subcommand"))
	for _, tc := range []struct {
		path string
		code int
		err  error
		want string
	}{
		{"schema", 0, nil, ""},
		{"schema", 3, errors.New("invalid schema query"), "schema"},
		{"version", 0, nil, ""},
		{"audit/tail", 0, nil, ""},
		{"calendar", 0, nil, ""},
		{"calendar", 3, unknown, "unresolved"},
		{"dingtalk-tag/connect", 3, unknown, "unresolved"},
	} {
		cmd := findPolicyCommand(t, root, tc.path)
		if got := commandAuditSurface(cmd, cmdpolicy.CommandPath(cmd), tc.code, tc.err, cmdpolicy.Observation{}); got != tc.want {
			t.Errorf("%s exit %d: surface=%q, want %q", tc.path, tc.code, got, tc.want)
		}
	}
}

// 自定义错误的 Unwrap 可能由扩展实现。观察者自身分类出错时，不能影响已经裁决的命令结果。
type panicUnwrapAuditError struct {
	called bool
}

func (*panicUnwrapAuditError) Error() string { return "external error" }

func (e *panicUnwrapAuditError) Unwrap() error {
	e.called = true
	panic("broken external error")
}

func TestCrossPlatformCoverageCommandAuditSurvivesErrorProjectionPanic(t *testing.T) {
	dir := isolateCommandAuditForTest(t)
	cause := &panicUnwrapAuditError{}
	newCommandAudit().afterCommand(nil, nil, 5, cause)
	if !cause.called {
		t.Fatal("observer did not classify the terminal error")
	}
	if _, err := os.Stat(filepath.Join(dir, "commands")); !os.IsNotExist(err) {
		t.Fatalf("observer published an incomplete event: %v", err)
	}
}
