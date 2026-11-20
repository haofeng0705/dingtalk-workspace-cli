package app

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/DingTalk-Real-AI/dingtalk-workspace-cli/internal/helpers"

	"github.com/DingTalk-Real-AI/dingtalk-workspace-cli/internal/audit"
	"github.com/DingTalk-Real-AI/dingtalk-workspace-cli/internal/corecmd/contract"
	apperrors "github.com/DingTalk-Real-AI/dingtalk-workspace-cli/internal/errors"
	"github.com/DingTalk-Real-AI/dingtalk-workspace-cli/internal/output"
	"github.com/spf13/cobra"
)

var (
	auditCSVWrite = func(writer *csv.Writer, record []string) error { return writer.Write(record) }
	auditCSVFlush = func(writer *csv.Writer) { writer.Flush() }
	auditCSVError = func(writer *csv.Writer) error { return writer.Error() }
	auditExit     = os.Exit
	auditVerify   = audit.VerifyFile
)

const (
	auditToolStream    = "tool"
	auditCommandStream = "command"
	auditStreamUsage   = "审计流：tool（工具调用）或 command（命令执行与裁剪策略）"
)

func auditStreamParam() []contract.ParamDecl {
	return []contract.ParamDecl{{Name: "stream", Enum: []string{auditToolStream, auditCommandStream}}}
}

func newAuditCommand() *cobra.Command {
	// Product-level Agent routing Decl (migrated from selection/audit.json
	// products.audit). Catalog assembly stamps provenance contract_final.
	contract.RegisterProductDecl(contract.ProductDecl{
		ID: "audit",
		HelpReferences: contract.HelpReferences{
			RelatedSkills: []string{"dingtalk-shared"},
			Documentation: []contract.HelpDocumentation{
				contract.SkillDocumentation("DWS 运行契约", "dingtalk-shared", "references/runtime-contract.md"),
			},
		},
		Selection: contract.ProductSelectionDecl{
			AgentSummary: "查看、导出和校验本地操作审计日志",
			UseWhen: []string{
				"需要排查本机 CLI 操作审计记录，或验证审计文件完整性",
			},
			AvoidWhen: []string{
				"查钉钉业务数据或发消息请用对应产品命令，不要用 audit",
			},
		},
	})
	cmd := &cobra.Command{
		Use:   "audit",
		Short: "操作审计日志管理",
		Long:  "查看、导出和校验本地操作审计日志。",
	}
	cmd.AddCommand(
		newAuditTailCommand(),
		newAuditExportCommand(),
		newAuditVerifyCommand(),
	)
	return cmd
}

func newAuditTailCommand() *cobra.Command {
	var n int
	var stream string
	cmd := &cobra.Command{
		Use:   "tail",
		Short: "查看最近的审计记录",
		RunE: func(cmd *cobra.Command, args []string) error {
			if n < 1 {
				return apperrors.NewValidation(
					fmt.Sprintf("--lines 必须为正整数，收到 %d", n),
					apperrors.WithReason("invalid_flag_value"),
				)
			}
			dir, err := auditStreamDir(stream)
			if err != nil {
				return err
			}
			file, err := audit.LatestAuditFile(dir)
			if err != nil {
				return fmt.Errorf("无审计记录: %w", err)
			}
			lines, err := tailFile(file, n)
			if err != nil {
				return err
			}
			for _, line := range lines {
				if _, err := fmt.Fprintln(cmd.OutOrStdout(), line); err != nil {
					return err
				}
			}
			return nil
		},
	}
	cmd.Flags().IntVarP(&n, "lines", "n", 20, "显示最近 N 条记录")
	cmd.Flags().StringVar(&stream, "stream", auditToolStream, auditStreamUsage)
	helpers.DeclareLeafMetadata(cmd, helpers.LeafSpec{
		Safety: contract.SafetySpec{
			Effect: "read", Risk: "low",
			Confirmation: "not_required", Idempotency: "idempotent",
		},
		Contract: helpers.LeafContract{
			Identity: contract.ToolIdentitySpec{
				ProductID:      "audit",
				Name:           "tail",
				CanonicalPath:  "audit.tail",
				CLIPath:        "audit tail",
				PrimaryCLIPath: "audit tail",
			},
			Description: "查看本地操作审计日志最近 N 条记录",
			Parameters:  auditStreamParam(),
			Interface: &contract.InterfaceSpec{
				Mode:         "local",
				Availability: "available",
				Reason:       "命令读取本地审计日志尾部，不绑定 pinned MCP RPC",
			},
			Selection: contract.SelectionSpec{
				AgentSummary: "查看本地操作审计日志最近 N 条记录",
				UseWhen:      []string{"需要快速查看最近写入的审计记录（默认最近 20 条）"},
				AvoidWhen: []string{
					"需要按日期范围整段导出用 audit export",
					"需要校验哈希链用 audit verify",
				},
				Examples: []string{
					"dws audit tail",
					"dws audit tail --stream command --lines 50",
				},
			},
		},
	})
	return cmd
}

func newAuditExportCommand() *cobra.Command {
	var since, until, format, stream string
	cmd := &cobra.Command{
		Use:   "export",
		Short: "导出审计日志",
		RunE: func(cmd *cobra.Command, args []string) error {
			dir, err := auditStreamDir(stream)
			if err != nil {
				return err
			}

			sinceDate := strings.ReplaceAll(since, "-", "")
			untilDate := strings.ReplaceAll(until, "-", "")

			files, err := audit.AuditFilesInRange(dir, sinceDate, untilDate)
			if err != nil {
				return fmt.Errorf("查找审计文件失败: %w", err)
			}
			if len(files) == 0 {
				return fmt.Errorf("指定范围内无审计文件")
			}

			switch format {
			case "jsonl":
				return exportJSONL(files, cmd.OutOrStdout())
			case "csv":
				return exportCSV(files, stream, cmd.OutOrStdout())
			default:
				return fmt.Errorf("不支持的格式: %s（可选 jsonl, csv）", format)
			}
		},
	}
	cmd.Flags().StringVar(&since, "since", "", "起始日期 (YYYY-MM-DD)")
	cmd.Flags().StringVar(&until, "until", "", "截止日期 (YYYY-MM-DD)")
	cmd.Flags().StringVar(&format, "format", "jsonl", "输出格式: jsonl 或 csv")
	cmd.Flags().StringVar(&stream, "stream", auditToolStream, auditStreamUsage)
	helpers.DeclareLeafMetadata(cmd, helpers.LeafSpec{
		Safety: contract.SafetySpec{
			Effect: "read", Risk: "low",
			Confirmation: "not_required", Idempotency: "idempotent",
		},
		Contract: helpers.LeafContract{
			Identity: contract.ToolIdentitySpec{
				ProductID:      "audit",
				Name:           "export",
				CanonicalPath:  "audit.export",
				CLIPath:        "audit export",
				PrimaryCLIPath: "audit export",
			},
			Description: "按日期范围导出本地操作审计日志（jsonl 或 csv）",
			Parameters:  auditStreamParam(),
			Interface: &contract.InterfaceSpec{
				Mode:         "local",
				Availability: "available",
				Reason:       "命令读取并导出本地审计日志文件，不绑定 pinned MCP RPC",
			},
			Selection: contract.SelectionSpec{
				AgentSummary: "按日期范围导出本地操作审计日志（jsonl 或 csv）",
				UseWhen:      []string{"需要把本地审计日志导出为 jsonl/csv，或按 --since/--until 取一段时间"},
				AvoidWhen: []string{
					"只看最近几条用 audit tail",
					"只校验哈希链完整性用 audit verify",
				},
				Examples: []string{
					"dws audit export --format jsonl",
					"dws audit export --stream command --since 2026-07-01 --until 2026-07-14 --format csv",
				},
			},
		},
	})
	return cmd
}

func newAuditVerifyCommand() *cobra.Command {
	var file, stream string
	cmd := &cobra.Command{
		Use:   "verify",
		Short: "校验审计日志哈希链完整性",
		RunE: func(cmd *cobra.Command, args []string) error {
			dir, err := auditStreamDir(stream)
			if err != nil {
				return err
			}
			target := file
			if target == "" {
				target, err = audit.LatestAuditFile(dir)
				if err != nil {
					return fmt.Errorf("无审计文件: %w", err)
				}
			}

			valid, brokenAt, verifyErr := auditVerify(target)
			if output.ResolveFormat(cmd, output.FormatTable) == output.FormatJSON {
				if verifyErr != nil && brokenAt == 0 {
					return fmt.Errorf("校验失败: %w", verifyErr)
				}
				payload := map[string]any{
					"valid":    valid,
					"file":     target,
					"brokenAt": brokenAt,
				}
				if verifyErr != nil {
					payload["reason"] = verifyErr.Error()
				}
				if err := output.WriteCommandPayload(cmd, payload, output.FormatTable); err != nil {
					return err
				}
				if !valid {
					auditExit(1)
				}
				return nil
			}
			if verifyErr != nil {
				return fmt.Errorf("校验失败: %w", verifyErr)
			}
			if valid {
				_, err = fmt.Fprintf(cmd.OutOrStdout(), "✓ %s 哈希链完整（全部通过）\n", filepath.Base(target))
			} else {
				_, err = fmt.Fprintf(cmd.OutOrStdout(), "✗ %s 哈希链在第 %d 行断裂\n", filepath.Base(target), brokenAt)
				auditExit(1)
			}
			return err
		},
	}
	cmd.Flags().StringVar(&file, "file", "", "指定审计文件路径（默认取所选审计流的最新文件）")
	cmd.Flags().StringVar(&stream, "stream", auditToolStream, auditStreamUsage)
	helpers.DeclareLeafMetadata(cmd, helpers.LeafSpec{
		Safety: contract.SafetySpec{
			Effect: "read", Risk: "low",
			Confirmation: "not_required", Idempotency: "idempotent",
		},
		Contract: helpers.LeafContract{
			Identity: contract.ToolIdentitySpec{
				ProductID:      "audit",
				Name:           "verify",
				CanonicalPath:  "audit.verify",
				CLIPath:        "audit verify",
				PrimaryCLIPath: "audit verify",
			},
			Description: "校验本地审计日志文件的哈希链完整性",
			Parameters:  auditStreamParam(),
			Interface: &contract.InterfaceSpec{
				Mode:         "local",
				Availability: "available",
				Reason:       "命令校验本地审计日志哈希链，不绑定 pinned MCP RPC",
			},
			Selection: contract.SelectionSpec{
				AgentSummary: "校验本地审计日志文件的哈希链完整性",
				UseWhen:      []string{"怀疑审计文件被篡改，或需要确认最新/指定文件哈希链是否完整"},
				AvoidWhen:    []string{"只浏览或导出日志内容时用 audit tail / audit export"},
				Examples: []string{
					"dws audit verify",
					"dws audit verify --file /path/to/audit.jsonl",
				},
			},
		},
	})
	return cmd
}

func auditDir() string {
	return audit.Dir(defaultConfigDir())
}

func auditStreamDir(stream string) (string, error) {
	switch stream {
	case auditToolStream:
		return auditDir(), nil
	case auditCommandStream:
		return audit.CommandDir(defaultConfigDir()), nil
	default:
		return "", apperrors.NewValidation("--stream 必须为 tool 或 command", apperrors.WithReason("invalid_flag_value"))
	}
}

func tailFile(path string, n int) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var lines []string
	scanner := audit.NewRecordScanner(f)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return lines, nil
}

func exportJSONL(files []string, out io.Writer) error {
	for _, file := range files {
		f, err := os.Open(file)
		if err != nil {
			return err
		}
		scanner := audit.NewRecordScanner(f)
		for scanner.Scan() {
			if _, err := fmt.Fprintln(out, scanner.Text()); err != nil {
				f.Close()
				return err
			}
		}
		f.Close()
		if err := scanner.Err(); err != nil {
			return err
		}
	}
	return nil
}

func exportCSV(files []string, stream string, out io.Writer) error {
	w := csv.NewWriter(out)

	header := []string{"timestamp", "execution_id", "user_id", "corp_id", "product", "command", "result", "duration_ms", "error_category"}
	record := toolCSVRecord
	if stream == auditCommandStream {
		header = []string{
			"ts", "command_id", "command_path", "surface", "result", "exit_code", "duration_ms", "cli_version",
			"error_category", "error_reason", "policy_state", "policy_source", "policy_view_hash", "policy_decision",
			"policy_target_path", "policy_rule_name", "policy_reason_code", "tool_execution_ids",
		}
		record = commandCSVRecord
	}
	if err := auditCSVWrite(w, header); err != nil {
		return fmt.Errorf("写入 CSV 表头失败: %w", err)
	}

	for _, file := range files {
		f, err := os.Open(file)
		if err != nil {
			return err
		}
		scanner := audit.NewRecordScanner(f)
		lineNum := 0
		for scanner.Scan() {
			lineNum++
			line := scanner.Bytes()
			if len(bytes.TrimSpace(line)) == 0 {
				continue
			}
			row, err := record(line)
			if err != nil {
				f.Close()
				return fmt.Errorf("解析审计记录失败 %s:%d: %w", file, lineNum, err)
			}
			if err := auditCSVWrite(w, row); err != nil {
				f.Close()
				return fmt.Errorf("写入 CSV 记录失败: %w", err)
			}
		}
		if err := scanner.Err(); err != nil {
			f.Close()
			return err
		}
		f.Close()
	}

	auditCSVFlush(w)
	if err := auditCSVError(w); err != nil {
		return fmt.Errorf("刷新 CSV 输出失败: %w", err)
	}
	return nil
}

func toolCSVRecord(line []byte) ([]string, error) {
	var evt audit.Event
	if err := json.Unmarshal(line, &evt); err != nil {
		return nil, err
	}
	return []string{
		evt.Timestamp.Format(time.RFC3339), evt.ExecutionID, evt.Actor.UserID, evt.Actor.CorpID,
		evt.Product, evt.Command, evt.Result, strconv.FormatInt(evt.DurationMs, 10), evt.ErrCategory,
	}, nil
}

func commandCSVRecord(line []byte) ([]string, error) {
	var evt audit.CommandEvent
	if err := json.Unmarshal(line, &evt); err != nil {
		return nil, err
	}
	policy := evt.Policy
	if policy == nil {
		policy = &audit.CommandPolicy{}
	}
	// []string 只含 JSON 可表示的值。保留数组，以便 CSV 消费方逐个关联工具记录。
	ids, _ := json.Marshal(evt.ToolExecutionIDs)
	return []string{
		evt.Timestamp.Format(time.RFC3339Nano), evt.CommandID, evt.CommandPath, evt.Surface,
		evt.Result, strconv.Itoa(evt.ExitCode), strconv.FormatInt(evt.DurationMs, 10), evt.CLIVersion,
		evt.ErrCategory, evt.ErrReason, policy.State, policy.Source, policy.ViewHash, policy.Decision,
		policy.TargetPath, policy.RuleName, policy.ReasonCode, string(ids),
	}, nil
}
