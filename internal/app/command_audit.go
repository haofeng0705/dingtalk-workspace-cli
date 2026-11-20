// Copyright 2026 Alibaba Group
// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"errors"
	"strings"
	"sync"
	"time"

	"github.com/DingTalk-Real-AI/dingtalk-workspace-cli/internal/audit"
	"github.com/DingTalk-Real-AI/dingtalk-workspace-cli/internal/cmdpolicy"
	"github.com/DingTalk-Real-AI/dingtalk-workspace-cli/internal/corecmd"
	apperrors "github.com/DingTalk-Real-AI/dingtalk-workspace-cli/internal/errors"
	"github.com/spf13/cobra"
)

var errCommandPanic = errors.New("command panicked")

type commandAuditKey struct{}

// 每次公开 CLI 调用有独立的收集器。工具可以并发完成，策略信息来自当前命令树。
type commandAudit struct {
	started     time.Time
	id          string
	mu          sync.Mutex
	observation cmdpolicy.Observation
	dispatched  bool
	tools       []string
}

func newCommandAudit() *commandAudit {
	if !audit.IsEnabled() {
		return nil
	}
	return &commandAudit{started: time.Now(), id: generateExecutionID()}
}

func (a *commandAudit) withContext(ctx context.Context) context.Context {
	if a == nil {
		return ctx
	}
	ctx = context.WithValue(ctx, commandAuditKey{}, a)
	return cmdpolicy.WithObserver(ctx, func(o cmdpolicy.Observation) {
		a.mu.Lock()
		defer a.mu.Unlock()
		// 失败恢复可能再次渲染帮助，保留首次实际拒绝的目标和用途。
		if !a.dispatched && a.observation.ReasonCode == "" {
			a.observation = o
		}
	})
}

// Cobra 返回后宿主可能为原错误附加帮助，随后渲染的帮助不属于用户的操作。
func (a *commandAudit) endDispatch() {
	if a != nil {
		a.mu.Lock()
		a.dispatched = true
		a.mu.Unlock()
	}
}

func (a *commandAudit) recordTool(id string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.tools = append(a.tools, id)
}

func (a *commandAudit) afterCommand(root, cmd *cobra.Command, code int, err error) {
	if a == nil {
		return
	}
	// 审计属于观察者。诊断既不参与退出码裁决，也不输出业务数据。
	defer func() {
		if recover() != nil {
			auditReport("command observer panicked")
		}
	}()
	a.mu.Lock()
	o := a.observation
	ids := append([]string{}, a.tools...)
	a.mu.Unlock()
	path := cmdpolicy.CommandPath(cmd)
	surface := commandAuditSurface(cmd, path, code, err, o)
	if surface == "" {
		return
	}
	if surface == "unresolved" {
		path = ""
	}
	now := time.Now()
	event := &audit.CommandEvent{
		EventType:        audit.CommandFinished,
		CommandID:        a.id,
		Timestamp:        now,
		DurationMs:       now.Sub(a.started).Milliseconds(),
		CLIVersion:       RawVersion(),
		CommandPath:      path,
		Surface:          surface,
		Result:           "success",
		ExitCode:         code,
		ToolExecutionIDs: ids,
	}
	if code != 0 {
		event.Result = "failure"
		event.ErrCategory, event.ErrReason = commandErrorFields(code, err)
	}
	if root != nil {
		s := cmdpolicy.For(root)
		p := &audit.CommandPolicy{
			State: string(s.State()), Source: s.Source(),
			ViewHash: s.ViewHash(), Decision: "not_evaluated",
		}
		if o.ReasonCode != "" {
			p.Decision, p.TargetPath, p.RuleName, p.ReasonCode = "deny", o.TargetPath, o.RuleName, o.ReasonCode
		} else if d, ok := s.Decision(path); ok && d.Allowed {
			p.Decision, p.TargetPath, p.RuleName = "allow", path, d.RuleName
		}
		event.Policy = p
	}
	if writeErr := audit.WriteCommand(defaultConfigDir(), event); writeErr != nil {
		auditReport("write command event failed: %v", writeErr)
	}
}

func commandAuditSurface(cmd *cobra.Command, path string, code int, err error, o cmdpolicy.Observation) string {
	if o.ReasonCode != "" {
		return o.Surface
	}
	if code == 0 && o.Surface == cmdpolicy.SurfaceHelp {
		return ""
	}
	switch path {
	case cmdpolicy.PolicyShowPath:
		return "policy_inspect"
	case "help", "schema":
		if code != 0 {
			return path
		}
		return ""
	case "version", "completion", cobra.ShellCompRequestCmd, cobra.ShellCompNoDescRequestCmd:
		return ""
	}
	if strings.HasPrefix(path, "completion/") || (code == 0 && strings.HasPrefix(path, "audit/")) {
		return ""
	}
	// 路径只能从真实节点取得。导航组及误拼的子命令不能归因到父组的业务操作。
	if path == "" || cmd == nil || !cmd.Runnable() {
		if code == 0 {
			return ""
		}
		return "unresolved"
	}
	if policy, ok, _ := corecmd.GroupPolicyFor(cmd); ok {
		if policy.Mode == corecmd.GroupNavigationOnly || (corecmd.GroupRecoversPositionals(cmd) && apperrors.IsUnknownInvocationError(err)) {
			if code == 0 {
				return ""
			}
			return "unresolved"
		}
	}
	return cmdpolicy.SurfaceExecute
}

// 退出码来自宿主最终裁决。仅复制已知的分类和原因，底层服务的错误文本可包含请求内容。
func commandErrorFields(code int, err error) (string, string) {
	category := commandExitCategories[code]
	var interrupted *processInterruption
	if errors.As(err, &interrupted) && code == interrupted.ExitCode() {
		return "internal", interrupted.Subtype()
	}
	var publication *outputPublicationError
	if errors.As(err, &publication) && code == 5 {
		return category, "output_publication_failed"
	}
	if err == errCommandPanic && code == 5 {
		return category, "internal_panic"
	}
	var typed *apperrors.Error
	if errors.As(err, &typed) && string(typed.Category) == category {
		switch typed.Reason {
		case "command_denied", "confirmation_required", "unknown_flag", "invalid_flag", "invalid_flag_value",
			"invalid_parameters", "missing_required_flags", "unknown_subcommand", "not_authenticated":
			return category, typed.Reason
		}
	}
	return category, ""
}

var commandExitCategories = map[int]string{
	apperrors.ExitCodeAPI:        "api",
	apperrors.ExitCodeAuth:       "auth",
	apperrors.ExitCodeValidation: "validation",
	apperrors.ExitCodePermission: "permission",
	apperrors.ExitCodeInternal:   "internal",
	apperrors.ExitCodeDiscovery:  "discovery",
	apperrors.ExitCodePartial:    "partial_failure",
	8:                            "wait",
	130:                          "interrupted",
	143:                          "interrupted",
}
