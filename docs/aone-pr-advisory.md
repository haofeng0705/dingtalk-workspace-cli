# GitHub PR 的非阻塞 Aone CLI-MCP 评测

本方案在 Pull Request 创建或更新后触发 Aone `cli_to_mcp` 评测，并将结构化结果更新到 PR 中的同一条 Comment。它是 Reviewer 的辅助信息，不是 Required Check，也不改变现有 Code Admission 门禁。

## 安全边界

- `pull_request_target` 只执行默认分支中受信任的 Workflow 和脚本。
- Workflow 不检出或执行 PR 代码，只把经过校验的 PR 元数据交给 Aone。
- 同仓库且作者关系为 `OWNER`、`MEMBER` 或 `COLLABORATOR` 的 PR 自动触发。
- 其他 PR 必须由维护者针对当前 SHA 添加 `aone-ci-approved` 标签；外部 PR 新推送后 Workflow 会移除旧标签、把粘性 Comment 更新为“当前 SHA 待批准”，使此前 SHA 的结论立即失效。
- Aone Pipeline 必须固定使用其受信任的 `main` 配置，再根据参数显式获取 GitHub PR SHA；不得加载 PR 修改后的 Pipeline 定义。
- Aone 回传结果仅在 `head_sha` 仍等于 PR 当前 head 时更新 Comment。

## GitHub 配置

在 Fork 仓库配置两个 Actions Secret：

| Secret | 用途 |
|---|---|
| `AONE_TRIGGER_URL` | 完整的 Aone `POST /openapi/v1/projects/{projectId}/pipelines/{pipelineId}/run` HTTPS 地址 |
| `AONE_PRIVATE_TOKEN` | 只允许触发目标 Pipeline 的 Aone Private Token |

Workflow 调用受信任的 Aone `main` Pipeline，并传入以下参数：

- `GITHUB_REPOSITORY`
- `GITHUB_PR_NUMBER`
- `GITHUB_BASE_SHA`
- `GITHUB_HEAD_SHA`
- `GITHUB_HEAD_REPOSITORY`
- `CORRELATION_ID`

### Fork 的兼容性基线

Fork 的远端仓库可能没有复制官方稳定版 tag，导致现有 `Interface Integrity` 无法选择兼容性基线。CI 仅在 `github.repository` 不是官方仓库时，通过公开 HTTPS 将官方 `v*` tag 读取到一次性 Runner 的本地 Git 仓库；官方仓库路径不会执行该 fetch，整个流程不包含 `git push`，也不会修改 fork 或官方仓库的远端 tag。若本地存在同名但指向不同提交的 tag，fetch 会失败并停止，不会强制覆盖。

## Aone Pipeline 要求

现有“开源 CLI 功能测试”流水线评测的是已发布 beta 包，不会检出 GitHub PR 源码，因此不能直接作为本方案的触发目标。建议在同一个 Aone 项目中新建专用 PR Pipeline，复用现有 Runner、凭据刷新、测试脚本、报告与制品能力，但将代码输入改为经过 SHA 校验的 GitHub PR revision。专用 Pipeline 的 Token、回传凭据和机器人地址必须全部使用 Aone Secret，不得沿用 YAML 中的明文或默认值。

Aone Pipeline 接收上述参数后，必须从固定 GitHub 基础仓库获取 PR ref，并验证精确 SHA：

```bash
git clone https://github.com/haofeng0705/dingtalk-workspace-cli.git github-pr
cd github-pr
git fetch origin "pull/${GITHUB_PR_NUMBER}/head"
git checkout --detach FETCH_HEAD
test "$(git rev-parse HEAD)" = "$GITHUB_HEAD_SHA"
```

生产化时仓库地址应由受信任配置固定，不能直接执行 PR 传入的任意 URL。

评测结束后生成以下结构化结果：

```json
{
  "schema_version": 1,
  "repository": "haofeng0705/dingtalk-workspace-cli",
  "pr_number": 17,
  "head_sha": "0123456789abcdef0123456789abcdef01234567",
  "run_id": "123456",
  "evaluation_result": "failed",
  "counts": {
    "total": 331,
    "passed": 310,
    "failed": 8,
    "errors": 3,
    "skipped": 10
  },
  "failure_type": "product_regression",
  "report_url": "https://aone.example/report/123456"
}
```

`evaluation_result` 允许 `passed`、`failed` 或 `error`。失败分类允许：

- `product_regression`
- `test_assertion`
- `fixture_or_data`
- `auth_or_credential`
- `network_or_platform`
- `pipeline_infrastructure`
- `none`

`report_url` 可留空；非空时必须是最长 2048 字符、不含用户名或密码的 HTTPS URL。Workflow 会先规范化 URL，再以 Markdown autolink 写入 Comment。

## 回传 GitHub

Aone 使用 GitHub App installation token，或灰度阶段使用单仓库 fine-grained token，触发：

```http
POST /repos/haofeng0705/dingtalk-workspace-cli/dispatches
```

请求中的 `event_type` 固定为 `aone-cli-to-mcp-completed`，上面的结构化结果作为 `client_payload`。GitHub 限制 `client_payload` 最多包含 10 个顶层属性，因此五个统计字段必须放在 `counts` 对象中；不得展开到顶层：

```json
{
  "event_type": "aone-cli-to-mcp-completed",
  "client_payload": {
    "schema_version": 1,
    "repository": "haofeng0705/dingtalk-workspace-cli",
    "pr_number": 17,
    "head_sha": "0123456789abcdef0123456789abcdef01234567",
    "run_id": "123456",
    "evaluation_result": "passed",
    "counts": {
      "total": 10,
      "passed": 10,
      "failed": 0,
      "errors": 0,
      "skipped": 0
    },
    "failure_type": "none",
    "report_url": "https://aone.example/report/123456"
  }
}
```

回传 Token 只能保存在 Aone Secret 中，不得写入 YAML、脚本、日志或评测报告。

## 灰度验证顺序

1. 将本方案先合入 Fork 的 `main`，使 `pull_request_target` 使用受信任版本。
2. 配置 Fork 的两个 Aone Secret。
3. 在 Fork 新建一个测试 PR，确认触发后出现“评测已触发”Comment。
4. 使用测试 payload 触发 `repository_dispatch`，确认同一条 Comment 被更新。
5. 将 Aone Pipeline 接入真实 `cli_to_mcp`，分别验证通过、业务失败和基础设施异常。
6. 保持 Workflow 非 Required，由 Reviewer 根据 Comment 判断。
