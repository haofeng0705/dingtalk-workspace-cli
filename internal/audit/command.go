// Copyright 2026 Alibaba Group
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"bytes"
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
	body, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("audit: marshal command: %w", err)
	}

	dir := CommandDir(configDir)
	writer, err := NewDateRotatingWriter(dir, retentionDays())
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, writer.Close()) }()
	return appendSealed(writer, NewChain(dir), body, func(prevHash, hash string) ([]byte, error) {
		// body 由上面的 Marshal 生成。用尾部封印替换右括号，换行也计入读取上限。
		suffix := commandSealSuffix(prevHash, hash)
		if len(body)+len(suffix) > MaxRecordBytes {
			return nil, fmt.Errorf("command event exceeds %d bytes", MaxRecordBytes)
		}
		return append(body[:len(body)-1], suffix...), nil
	})
}

// 命令流将两个哈希字段固定放在末尾。保留原始正文字节能覆盖字段顺序、
// 显式零值和将来增加的字段，并防止 JSON 解码器合并重复键后漏检改动。
func commandSealSuffix(prevHash, hash string) []byte {
	seal, _ := json.Marshal(struct {
		PrevHash string `json:"prev_hash"`
		Hash     string `json:"hash"`
	}{prevHash, hash})
	seal[0] = ','
	return seal
}

func commandHashBody(raw []byte, prevHash, hash string) ([]byte, error) {
	body, ok := bytes.CutSuffix(raw, commandSealSuffix(prevHash, hash))
	if !ok {
		return nil, errors.New("missing or noncanonical command seal")
	}
	// 原始记录已解析，校验器仅消费 body。本行不再使用时可复用扫描缓冲区。
	return append(body, '}'), nil
}
