// Copyright 2026 Alibaba Group
// Licensed under the Apache License, Version 2.0 (the "License");

package scripts_test

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestAonePRTriggerPostsExactNonBlockingContract(t *testing.T) {
	t.Parallel()

	type requestBody struct {
		Branch    string            `json:"branch"`
		CommitID  *string           `json:"commitId"`
		Params    map[string]string `json:"params"`
		Callbacks []any             `json:"callbacks"`
	}

	requestCh := make(chan requestBody, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("private-token"); got != "test-private-token" {
			t.Errorf("private-token header = %q", got)
		}
		if got := r.Header.Get("Content-Type"); got != "application/json" {
			t.Errorf("Content-Type = %q", got)
		}
		var body requestBody
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Errorf("decode request: %v", err)
		}
		requestCh <- body
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"success":true,"data":{"pipelineRunId":123456}}`)
	}))
	defer server.Close()

	root := repositoryRoot(t)
	outputPath := filepath.Join(t.TempDir(), "github-output")
	cmd := exec.Command("bash", filepath.Join(root, "scripts", "ci", "trigger-aone-pr-evaluation.sh"))
	cmd.Env = append(os.Environ(),
		"AONE_TRIGGER_URL="+server.URL,
		"AONE_PRIVATE_TOKEN=test-private-token",
		"GITHUB_REPOSITORY=haofeng0705/dingtalk-workspace-cli",
		"GITHUB_PR_NUMBER=17",
		"GITHUB_BASE_SHA="+strings.Repeat("a", 40),
		"GITHUB_HEAD_SHA="+strings.Repeat("b", 40),
		"GITHUB_HEAD_REPOSITORY=haofeng0705/dingtalk-workspace-cli",
		"CORRELATION_ID=haofeng0705/dingtalk-workspace-cli/pull/17/"+strings.Repeat("b", 40),
		"GITHUB_OUTPUT="+outputPath,
	)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("trigger script failed: %v\n%s", err, output)
	}
	if strings.Contains(string(output), "test-private-token") {
		t.Fatal("trigger script leaked the Aone private token")
	}

	request := <-requestCh
	if request.Branch != "main" || request.CommitID != nil {
		t.Fatalf("trusted Aone revision = branch %q commit %#v", request.Branch, request.CommitID)
	}
	if len(request.Callbacks) != 0 {
		t.Fatalf("callbacks = %#v, want explicit empty callbacks", request.Callbacks)
	}
	wantParams := map[string]string{
		"GITHUB_REPOSITORY":      "haofeng0705/dingtalk-workspace-cli",
		"GITHUB_PR_NUMBER":       "17",
		"GITHUB_BASE_SHA":        strings.Repeat("a", 40),
		"GITHUB_HEAD_SHA":        strings.Repeat("b", 40),
		"GITHUB_HEAD_REPOSITORY": "haofeng0705/dingtalk-workspace-cli",
		"CORRELATION_ID":         "haofeng0705/dingtalk-workspace-cli/pull/17/" + strings.Repeat("b", 40),
	}
	if fmt.Sprint(request.Params) != fmt.Sprint(wantParams) {
		t.Fatalf("params = %#v, want %#v", request.Params, wantParams)
	}

	githubOutput, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("read GitHub output: %v", err)
	}
	if !strings.Contains(string(githubOutput), "run_id=123456") {
		t.Fatalf("GitHub output = %q, want run id", githubOutput)
	}
}

func TestAonePRTriggerRejectsCleartextNonLoopbackEndpoint(t *testing.T) {
	t.Parallel()

	root := repositoryRoot(t)
	cmd := exec.Command("bash", filepath.Join(root, "scripts", "ci", "trigger-aone-pr-evaluation.sh"))
	cmd.Env = append(os.Environ(),
		"AONE_TRIGGER_URL=http://aone.example.test/run",
		"AONE_PRIVATE_TOKEN=test-private-token",
		"GITHUB_REPOSITORY=haofeng0705/dingtalk-workspace-cli",
		"GITHUB_PR_NUMBER=17",
		"GITHUB_BASE_SHA="+strings.Repeat("a", 40),
		"GITHUB_HEAD_SHA="+strings.Repeat("b", 40),
		"GITHUB_HEAD_REPOSITORY=haofeng0705/dingtalk-workspace-cli",
		"CORRELATION_ID=correlation",
		"GITHUB_OUTPUT="+filepath.Join(t.TempDir(), "github-output"),
	)
	output, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("cleartext Aone endpoint unexpectedly passed: %s", output)
	}
	if !strings.Contains(string(output), "must use HTTPS") {
		t.Fatalf("cleartext rejection = %q", output)
	}
}

func TestAonePRAdvisoryWorkflowSecurityContract(t *testing.T) {
	t.Parallel()

	root := repositoryRoot(t)
	triggerData, err := os.ReadFile(filepath.Join(root, ".github", "workflows", "aone-pr-evaluation.yml"))
	if err != nil {
		t.Fatal(err)
	}
	trigger := string(triggerData)
	for _, want := range []string{
		"pull_request_target:",
		"types: [opened, synchronize, reopened, ready_for_review, labeled]",
		"pull.head.sha !== expectedHead",
		"pull.base.sha !== expectedBase",
		"pull.head.repo?.full_name === `${owner}/${repo}`",
		"['OWNER', 'MEMBER', 'COLLABORATOR']",
		"aone-ci-approved",
		"context.payload.action === 'synchronize'",
		"github.rest.issues.removeLabel",
		"must be granted again for ${expectedHead}",
		"ref: ${{ steps.authorize.outputs.base_sha }}",
		"persist-credentials: false",
		"continue-on-error: true",
		"currentPull.head.sha !== process.env.HEAD_SHA",
		"stale trigger status ignored",
		"本评测仅供 Reviewer 参考，不阻塞 PR 合并",
	} {
		if !strings.Contains(trigger, want) {
			t.Errorf("trigger workflow missing contract marker %q", want)
		}
	}
	for _, forbidden := range []string{
		"pull_request:\n",
		"github.event.pull_request.head.repo.clone_url",
		"statuses: write",
		"checks: write",
	} {
		if strings.Contains(trigger, forbidden) {
			t.Errorf("trigger workflow must not contain %q", forbidden)
		}
	}

	resultData, err := os.ReadFile(filepath.Join(root, ".github", "workflows", "aone-pr-comment.yml"))
	if err != nil {
		t.Fatal(err)
	}
	result := string(resultData)
	for _, want := range []string{
		"repository_dispatch:",
		"types: [aone-cli-to-mcp-completed]",
		"payload.repository !== expectedRepository",
		"pull.head.sha !== headSha",
		"comment.body?.includes(marker)",
		"github.rest.issues.updateComment",
		"github.rest.issues.createComment",
		"本评测仅供 Reviewer 参考，不阻塞 PR 合并",
	} {
		if !strings.Contains(result, want) {
			t.Errorf("result workflow missing contract marker %q", want)
		}
	}
	for _, forbidden := range []string{
		"actions/checkout",
		"statuses: write",
		"checks: write",
	} {
		if strings.Contains(result, forbidden) {
			t.Errorf("result workflow must not contain %q", forbidden)
		}
	}
}

func repositoryRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatalf("resolve repository root: %v", err)
	}
	return root
}
