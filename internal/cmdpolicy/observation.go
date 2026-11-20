// Copyright 2026 Alibaba Group
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cmdpolicy

import (
	"context"
	"errors"

	apperrors "github.com/DingTalk-Real-AI/dingtalk-workspace-cli/internal/errors"
	"github.com/spf13/cobra"
)

const (
	SurfaceExecute = "execute"
	SurfaceHelp    = "help"
	SurfaceSchema  = "schema"
)

// Observation 只描述当前调用实际触及的入口和拒绝。普通帮助没有拒绝原因。
type Observation struct {
	Surface    string
	TargetPath string
	ReasonCode string
	RuleName   string
}

type observerKey struct{}

// WithObserver 将接收方绑定到本次调用，不改变命令树上的策略快照。
func WithObserver(ctx context.Context, receive func(Observation)) context.Context {
	return context.WithValue(ctx, observerKey{}, receive)
}

// Observe 报告执行、帮助或 Schema 入口实际给出的拒绝，原样返回调用方的错误。
// HelpFunc 也用 nil 报告成功展示帮助，区分普通帮助和业务执行。
func Observe(cmd *cobra.Command, surface string, err error) error {
	// 显式 help 命令解析的目标节点可能没有执行过，只有 root 拥有此次调用的上下文。
	ctx := cmd.Root().Context()
	if ctx == nil {
		return err
	}
	receive, _ := ctx.Value(observerKey{}).(func(Observation))
	if receive == nil {
		return err
	}
	var typed *apperrors.Error
	switch {
	case errors.As(err, &typed) && typed.Reason == "command_denied":
		path, _ := typed.Details["path"].(string)
		reasonCode, _ := typed.Details["reason_code"].(string)
		rule, _ := typed.Details["rule_name"].(string)
		receive(Observation{Surface: surface, TargetPath: path, ReasonCode: reasonCode, RuleName: rule})
	case err == nil && surface == SurfaceHelp:
		receive(Observation{Surface: surface})
	}
	return err
}
