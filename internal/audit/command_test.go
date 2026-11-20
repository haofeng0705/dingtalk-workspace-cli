// Copyright 2026 Alibaba Group
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestCrossPlatformCoverageCommandStreamIndependentAndLocal(t *testing.T) {
	configDir := t.TempDir()
	auditDir := t.TempDir()
	t.Setenv(EnvAudit, "1")
	t.Setenv(EnvAuditDir, auditDir)
	var posted atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var event Event
		if err := json.NewDecoder(r.Body).Decode(&event); err != nil || event.ExecutionID != "legacy-1" {
			t.Errorf("unexpected forward execution_id=%q err=%v", event.ExecutionID, err)
		}
		posted.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	t.Setenv(EnvForwardURL, server.URL)
	t.Setenv(EnvForwardRedact, "none")
	tool := &Event{Timestamp: time.Date(2026, 11, 17, 0, 0, 0, 0, time.UTC), ExecutionID: "legacy-1",
		Product: "calendar", Command: "event_list", Result: "success", CLIVersion: "v1", OS: "darwin", Arch: "arm64"}
	sink, err := BuildSink(configDir, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := sink.Emit(tool); err != nil {
		t.Fatal(err)
	}
	if err := sink.Close(); err != nil {
		t.Fatal(err)
	}
	// 旧工具事件的精确哈希来自改动前的字段顺序和编码。
	if tool.Hash != "5f394c208bad9821c448edf0e64e07e8e0d7a5a5b09ec479916552d26f2277f4" {
		t.Fatalf("legacy hash changed: %s", tool.Hash)
	}
	command := CommandEvent{CommandID: "command-1", Surface: "help", CommandPath: "calendar", Result: "success",
		Policy: &CommandPolicy{State: "active", Decision: "deny", TargetPath: "calendar", ReasonCode: "all_children_denied"}}
	if err := WriteCommand(configDir, &command); err != nil {
		t.Fatal(err)
	}
	if posted.Load() != 1 {
		t.Fatalf("forwarded %d records", posted.Load())
	}
	file, err := LatestAuditFile(CommandDir(configDir))
	if err != nil {
		t.Fatal(err)
	}
	if valid, at, err := VerifyFile(file); !valid || err != nil {
		t.Fatalf("new chain: %v at %d: %v", valid, at, err)
	}
	raw, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{`"event_type":"command.finished"`, `"exit_code":0`, `"tool_execution_ids":[]`, `"prev_hash":""`} {
		if !bytes.Contains(raw, []byte(expected)) {
			t.Fatalf("missing %s in %s", expected, raw)
		}
	}
	for _, change := range [][2]string{
		{"all_children_denied", "channel_not_allowed"},
		{`"exit_code":0,`, ""},
		{`"tool_execution_ids":[]`, `"tool_execution_ids":["unexpected"]`},
		{`"surface":`, `"extra":"unexpected","surface":`},
		{"command.finished", "other"},
	} {
		tampered := bytes.Replace(raw, []byte(change[0]), []byte(change[1]), 1)
		if err := os.WriteFile(file, tampered, 0o600); err != nil {
			t.Fatal(err)
		}
		if valid, at, err := VerifyFile(file); valid || at != 1 || err == nil {
			t.Fatalf("tampering %v: valid=%v at=%d err=%v", change, valid, at, err)
		}
	}
	old, err := LatestAuditFile(auditDir)
	if err != nil {
		t.Fatal(err)
	}
	if valid, at, err := VerifyFile(old); !valid || err != nil {
		t.Fatalf("legacy chain: %v at %d: %v", valid, at, err)
	}
}

func TestCrossPlatformCoverageCommandWritersShareDailyChain(t *testing.T) {
	const writers = 8
	configDir := t.TempDir()
	t.Setenv(EnvAuditDir, "")
	t.Setenv(EnvAudit, "1")
	if got := CommandDir(configDir); got != filepath.Join(configDir, "audit", "commands") {
		t.Fatalf("command dir: %s", got)
	}
	var wg sync.WaitGroup
	for id := range writers {
		wg.Go(func() {
			if err := WriteCommand(configDir, &CommandEvent{CommandID: fmt.Sprint(id)}); err != nil {
				t.Errorf("append %d: %v", id, err)
			}
		})
	}
	wg.Wait()
	path, err := LatestAuditFile(CommandDir(configDir))
	if err != nil {
		t.Fatal(err)
	}
	if valid, at, err := VerifyFile(path); !valid || err != nil {
		t.Fatalf("concurrent chain: valid=%v line=%d err=%v", valid, at, err)
	}
	data, err := os.ReadFile(path)
	if err != nil || bytes.Count(data, []byte{'\n'}) != writers {
		t.Fatalf("record count after %d writes: %s err=%v", writers, data, err)
	}
	t.Setenv(EnvAudit, "0")
	disabled := t.TempDir()
	if err := WriteCommand(disabled, &CommandEvent{}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(CommandDir(disabled)); !os.IsNotExist(err) {
		t.Fatalf("disabled command stream dir: %v", err)
	}
	t.Setenv(EnvAudit, "1")
	t.Setenv(EnvAuditDir, path)
	if err := WriteCommand(configDir, &CommandEvent{}); err == nil {
		t.Fatal("expected a diagnostic error for unusable command directory")
	}
}
