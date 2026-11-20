// Copyright 2026 Alibaba Group
// SPDX-License-Identifier: Apache-2.0

package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/DingTalk-Real-AI/dingtalk-workspace-cli/internal/audit"
	"github.com/DingTalk-Real-AI/dingtalk-workspace-cli/internal/auth"
	"github.com/DingTalk-Real-AI/dingtalk-workspace-cli/internal/executor"
	"github.com/DingTalk-Real-AI/dingtalk-workspace-cli/internal/testseam"
	"github.com/spf13/cobra"
)

func TestCrossPlatformCoverageCommandAuditLinksPersistedTools(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("DWS_CONFIG_DIR", dir)
	t.Setenv("DWS_KEYCHAIN_DIR", t.TempDir())
	t.Setenv(audit.EnvAuditDir, dir)
	t.Setenv(audit.EnvAudit, "1")
	t.Setenv(audit.EnvForwardURL, "")
	testseam.Swap(t, &loadTokenForProfile, func(string, string) (*auth.TokenData, error) { return nil, nil })
	resetAuditIdentityCache()
	t.Cleanup(resetAuditIdentityCache)

	sink, err := audit.BuildSink(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sink.Close() })
	root := &cobra.Command{Use: "dws"}
	leaf := &cobra.Command{Use: "list", Run: func(*cobra.Command, []string) {}}
	root.AddCommand(leaf)
	first, second := newCommandAudit(), newCommandAudit()
	firstCtx, secondCtx := first.withContext(t.Context()), second.withContext(t.Context())
	emit := func(ctx context.Context, target audit.Sink, id string) {
		emitAudit(ctx, target, id, time.Now(), executor.Invocation{Tool: "list"}, "", nil, "test")
	}
	var wg sync.WaitGroup
	wg.Go(func() { emit(firstCtx, sink, "first-tool-a") })
	wg.Go(func() { emit(firstCtx, sink, "first-tool-b") })
	wg.Go(func() { emit(secondCtx, sink, "second-tool") })
	wg.Wait()
	emit(firstCtx, audit.NopSink{}, "disabled-tool")
	emit(firstCtx, &auditCoverageSink{emitErr: errors.New("failed to write")}, "unwritten-tool")
	first.afterCommand(root, leaf, 0, nil)
	second.afterCommand(root, leaf, 0, nil)

	readStream := func(dir string) [][]byte {
		t.Helper()
		file, err := audit.LatestAuditFile(dir)
		if err != nil {
			t.Fatal(err)
		}
		if valid, line, err := audit.VerifyFile(file); !valid || err != nil {
			t.Fatalf("verify line=%d err=%v", line, err)
		}
		data, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		return bytes.Split(bytes.TrimSpace(data), []byte{'\n'})
	}
	var written []string
	for _, row := range readStream(dir) {
		var event audit.Event
		if err := json.Unmarshal(row, &event); err != nil {
			t.Fatal(err)
		}
		written = append(written, event.ExecutionID)
	}
	slices.Sort(written)
	if !slices.Equal(written, []string{"first-tool-a", "first-tool-b", "second-tool"}) {
		t.Fatalf("persisted tool IDs = %v", written)
	}
	commands := readStream(audit.CommandDir(dir))
	if len(commands) != 2 || first.id == second.id || first.id == "" || second.id == "" {
		t.Fatalf("command count=%d, ids=%q,%q", len(commands), first.id, second.id)
	}
	for i, want := range [][]string{written[:2], written[2:]} {
		var event audit.CommandEvent
		if err := json.Unmarshal(commands[i], &event); err != nil {
			t.Fatal(err)
		}
		slices.Sort(event.ToolExecutionIDs)
		if !slices.Equal(event.ToolExecutionIDs, want) || event.CommandID != []string{first.id, second.id}[i] {
			t.Fatalf("unexpected command association: %+v", event)
		}
	}
}
