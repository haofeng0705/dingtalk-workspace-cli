// Copyright 2026 Alibaba Group
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"time"
)

const CommandFinished = "command.finished"

// CommandEvent records the final public CLI outcome, including commands with
// no tool calls. It has no arguments, error message, or credential fields.
type CommandEvent struct {
	EventType        string         `json:"event_type"`
	CommandID        string         `json:"command_id"`
	Timestamp        time.Time      `json:"ts"`
	DurationMs       int64          `json:"duration_ms"`
	CLIVersion       string         `json:"cli_version"`
	CommandPath      string         `json:"command_path,omitempty"`
	Surface          string         `json:"surface"`
	Result           string         `json:"result"`
	ExitCode         int            `json:"exit_code"`
	ErrCategory      string         `json:"error_category,omitempty"`
	ErrReason        string         `json:"error_reason,omitempty"`
	Policy           *CommandPolicy `json:"policy,omitempty"`
	ToolExecutionIDs []string       `json:"tool_execution_ids"`
}

type CommandPolicy struct {
	State      string `json:"state"`
	Source     string `json:"source,omitempty"`
	ViewHash   string `json:"view_hash,omitempty"`
	Decision   string `json:"decision"`
	TargetPath string `json:"target_path,omitempty"`
	RuleName   string `json:"rule_name,omitempty"`
	ReasonCode string `json:"reason_code,omitempty"`
}

func CommandDir(configDir string) string {
	return filepath.Join(Dir(configDir), "commands")
}

// WriteCommand uses a local-only writer. Its lifetime extends through final
// process cleanup even when the tool sink has already been closed.
func WriteCommand(configDir string, event *CommandEvent) (err error) {
	if !IsEnabled() {
		return nil
	}
	record := *event
	record.EventType = CommandFinished
	if record.ToolExecutionIDs == nil {
		record.ToolExecutionIDs = []string{}
	}
	raw, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("audit: marshal command: %w", err)
	}
	body, err := commandHashBody(raw)
	if err != nil {
		return err
	}

	dir := CommandDir(configDir)
	writer, err := NewDateRotatingWriter(dir, retentionDays())
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, writer.Close()) }()
	return appendSealed(writer, NewChain(dir), body, func(prevHash, hash string) ([]byte, error) {
		return json.Marshal(struct {
			CommandEvent
			PrevHash string `json:"prev_hash"`
			Hash     string `json:"hash"`
		}{record, prevHash, hash})
	})
}

// Hash all persisted command fields, including explicit zero and empty values
// and future fields. Using the same projection on read and write keeps new
// command fields covered without changing the legacy tool projection.
func commandHashBody(raw []byte) ([]byte, error) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return nil, err
	}
	delete(fields, "prev_hash")
	delete(fields, "hash")
	return json.Marshal(fields)
}
