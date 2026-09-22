# Drydock 交付报告

> 报告日期：2026-09-22 ｜ 版本：v0.1.0 ｜ 仓库：`github.com/drydock-updater/drydock`
> 本报告所有"已验证"结论均在 2026-09-22 当天于本机（Git Bash, PATH 含 `/d/github/.tools/go/bin`）实际执行核查命令得出；未执行的项目在 §7 如实声明。

---

## 1. 方向裁决依据

**为什么做 Drydock：继任 containrrr/watchtower，填补"安全更新闭环"缝隙。**

依据《全网调研-维护需求与产品机会-2026-09-21》（`D:\github\全网调研-维护需求与产品机会-2026-09-21.md`）：

- **1.3 节 Watchtower 行（第 36 行）**：Watchtower（13k★）"停更 2 年+，issue #2067 确认死亡"；需求信号为"自托管更新管理刚需仍在"；继任者现状是"WUD 只做监控+白名单更新"——**无成熟直接接盘 fork**。该表所属 1.3 节标题即"已归档/弃养但需求旺盛——'接盘做继任者'机会"。
- **2.2 节第⑦条（第 92–94 行，C 级"有缝隙"）**：「自托管安全更新管理器（预演+回滚）」——痛点是自托管社区对破坏性变更的恐惧（"Too scared to upgrade Immich"等热帖），Watchtower 式自动更新被视为危险；查重结论为 **"Watchtower 已死 2 年+；WUD（5k★）只做监控+白名单；'更新前读 changelog/破坏性变更预判 + 快照 + 可回滚'全链路无人覆盖"**。
- **横向结论第 2 条（第 147 行）**：所有 A/C 级机会的共性是"检测过剩、行动缺失"，"做闭环的最后一步是 2026 年最一致的缝隙"。

Drydock 的定位与上述裁决逐条对应：在 watchtower 十年验证的"监控 → 拉新镜像 → 重建容器"核心循环之上，补齐**预检 → 快照 → 健康门禁 → 自动回滚**的安全闭环，正是 2.2⑦ 点名"无人覆盖"的那段链路。

---

## 2. 交付物清单

### 2.1 顶层结构（`ls -la D:\github\drydock` 实测）

```
drydock/
├── main.go / go.mod / go.sum          # module: github.com/drydock-updater/drydock
├── README.md          (11,656 B)      # 中文项目说明：四支柱、快速上手
├── MIGRATION.md       (10,043 B)      # watchtower→drydock 迁移指南（compose 对照）
├── CHANGELOG.md       ( 6,330 B)      # Keep a Changelog 格式，v0.1.0 - 2026-09-22
├── NOTICE             ( 1,267 B)      # Apache-2.0 §4(b) 上游修改声明
├── FOLLOWUPS.md       ( 4,199 B)      # 10 条 P2 遗留项（社区待办）
├── LICENSE.md / SECURITY.md / CONTRIBUTING.md / code_of_conduct.md
├── cmd/               # root.go, notify-upgrade.go（组件组合层）
├── internal/          # actions(含 safety.go 编排), flags, meta, util
├── pkg/               # 15 个包（见 2.2）
├── docs/              # 20 个 md 文档，含 safe-update.md(159 行)、arguments.md(新旗标已收录)
├── scripts/ dockerfiles/ .github/ grafana/ prometheus/ tplprev/  # 继承自上游的工程设施
```

### 2.2 Go 包与代码量（实测）

`ls -R pkg internal` 确认 **pkg 下 15 个包**：`api` `api/metrics` `api/update` `container` `filters` `healthgate` `lifecycle` `metrics` `notifications` `precheck` `registry`（含 `auth`/`digest`/`helpers`/`manifest` 子包）`rollback` `safeflow` `session` `sorter` `types` `updatereport`；**internal 下 4 个包**：`actions` `flags` `meta` `util`。

代码量（`find . -name '*.go' | xargs wc -l | tail -1` 实测）：

| 范围 | 文件数 | 行数 |
|---|---|---|
| 全仓 `*.go` | 111 | **20,649** |
| 安全环四支柱+契约（precheck/rollback/healthgate/safeflow，含测试） | — | 6,738 |
| 其中四支柱**源码**（不含 `_test.go`） | — | 2,178 |
| 周期报告 `pkg/updatereport` 源码 | 3 | 480 |
| 安全环编排 `internal/actions/safety.go` | 1 | 286 |

四个 v0.1 功能包源码构成：`pkg/safeflow`（契约，safeflow.go 278 行 + report.go 118 行）、`pkg/precheck`（precheck.go 226 + semver.go 335）、`pkg/rollback`（snapshot.go 437 + restore.go 480）、`pkg/healthgate`（healthgate.go 304）。

### 2.3 safeflow 共享契约（`pkg/safeflow/safeflow.go`）

- 四接口：`Prechecker`（safeflow.go:131）、`Snapshotter`（:200）、`HealthGater`（:258）、`Rollbacker`（:272）；哨兵错误 `ErrHealthTimeout`/`ErrUnhealthy`/`ErrSnapshotInvalid`/`ErrRollbackImageMissing`（:65-82）；容器豁免标签 `com.drydock.updater.precheck`（:60）。
- **零冲突规则**（safeflow.go:36-39）：`pkg/precheck`、`pkg/rollback`、`pkg/healthgate`、`pkg/updatereport` 只准 import safeflow、标准库与上游依赖，**互相不依赖**；组合仅发生在 cmd 层。
- 契约注释逐条钉住与上游 watchtower 更新流的对接缝（update.go:36-38 staleness 之后、:85-97 停止之前、:224-228 启动之后、client.go:248-300 重建路径）。

---

## 3. 架构与安全闭环四支柱

上游核心循环（容器监控 → 拉新镜像 → 优雅停止 → 重建）保持原样；四支柱围绕它编排（编排层 `internal/actions/safety.go`，组件组装在 cmd 层）：

```
监控 → 拉新镜像 → [① 预检] → [② 快照] → 停止+重建 → [③ 健康门禁] → 成功
                                                  ↘ 不健康 → [④ 自动回滚]
```

1. **预检 `pkg/precheck`**——把坏更新挡在门外。容器被停止**之前**做策略评估：semver 跨大版本阻断（降级放行并标注）、预发布 tag 阻断、非 semver tag 的 `allow`/`block` 策略、`--require-healthcheck` 强制；目标镜像 OCI 标签（`org.opencontainers.image.*`）作为 changelog 证据进报告；`com.drydock.updater.precheck=false` 标签单容器豁免。被否决容器本周期不被触碰（状态 `skipped`）。纯本地数据，不产生额外 registry 请求（safety.go:115-141）。
2. **快照 `pkg/rollback`（FileSnapshotStore）**——留下还原点。任何容器被停止前对其 `docker inspect` **深拷贝**并原子落盘（临时文件 + rename），按容器名组织，Drydock 重启后仍可回滚；深拷贝是必须的——上游重建流程会在原地改写 inspect（GetCreateConfig/GetCreateHostConfig/GetNetworkConfig，safeflow.go:141-145 注释钉住三处原地突变点）。默认脱敏：快照 JSON 中环境变量值替换为占位符，真实值写独立 `0600` sidecar 文件，读取时自动回填。
3. **健康门禁 `pkg/healthgate`**——上线前先体检。新容器启动后轮询：有 HEALTHCHECK 等到 `healthy` 放行，`unhealthy`/退出即失败，窗口耗尽报超时；无 HEALTHCHECK 退化为运行态单次确认；轮询间隔收敛到 `[100ms, timeout/2]` 保证至少两次探测。门禁只观察、绝不重启容器（safeflow.go:257）。
4. **自动回滚 `pkg/rollback`（Restorer）**——不健康自动止损。门禁失败且 `--rollback-on-unhealthy=true` 且有快照时，按快照**原样重建旧容器**（原镜像 ID、配置、网络、原名，走上游验证过的 create→connect→start 路径）；失败新容器改名 `drydock-failed-<name>-<时间戳>` 保留并截取最后 50 行日志；回滚按快照钉住的**不可变镜像 ID**（`sha256:...`）创建而非 tag，杜绝"同名 tag 已被重新 pull 指向刚失败的新镜像"的投毒窗口。

配套：**周期报告 `pkg/updatereport`**——每容器一行 `NAME / STATUS / IMAGE / PRECHECK / HEALTH / ROLLBACK / ERROR`，控制台始终输出，可经 shoutrrr 推送；安静周期不打扰。

---

## 4. 新旗标用法速查

13 个安全环旗标，全部绑定 `DRYDOCK_*` 环境变量（定义 `internal/flags/flags.go:216-287`，默认值 `flags.go:506-525`，文档 `docs/arguments.md:516-587`）。上游全部 `WATCHTOWER_*` 旗标/环境变量/容器标签原样保留。

| 旗标 | 环境变量 | 默认 | 作用 |
|---|---|---|---|
| `--precheck` | `DRYDOCK_PRECHECK` | `true` | 更新前策略门总开关 |
| `--block-major` | `DRYDOCK_BLOCK_MAJOR` | `true` | semver 跨大版本阻断（降级不阻断） |
| `--block-prerelease` | `DRYDOCK_BLOCK_PRERELEASE` | `true` | 目标 tag 含 `-beta.1`/`rc.1` 等预发布段时阻断 |
| `--precheck-unknown-tag` | `DRYDOCK_PRECHECK_UNKNOWN_TAG` | `allow` | 非 semver tag（latest/日期 tag/digest-pin）策略：`allow`/`block` |
| `--require-healthcheck` | `DRYDOCK_REQUIRE_HEALTHCHECK` | `false` | 目标镜像无 HEALTHCHECK 即阻断 |
| `--health-gate` | `DRYDOCK_HEALTH_GATE` | `true` | 健康门禁总开关；false 还原 watchtower 行为 |
| `--snapshot` | `DRYDOCK_SNAPSHOT` | `true` | 更新前快照总开关 |
| `--snapshot-redact-env` | `DRYDOCK_SNAPSHOT_REDACT_ENV` | `true` | 快照环境变量值脱敏（真实值存 0600 sidecar） |
| `--snapshot-dir` | `DRYDOCK_SNAPSHOT_DIR` | `/var/lib/drydock/snapshots` | 快照目录（启动时创建，须可写） |
| `--snapshot-keep` | `DRYDOCK_SNAPSHOT_KEEP` | `1` | 每容器成功后保留的快照数 |
| `--health-timeout` | `DRYDOCK_HEALTH_TIMEOUT` | `60s` | 门禁窗口上限 |
| `--health-interval` | `DRYDOCK_HEALTH_INTERVAL` | `5s` | 门禁轮询间隔（收敛到 `[100ms, timeout/2]`） |
| `--rollback-on-unhealthy` | `DRYDOCK_ROLLBACK_ON_UNHEALTHY` | `true` | 门禁失败自动回滚；要求 `--health-gate` 与 `--snapshot` 同开 |

速查：

```bash
# 完全还原 watchtower 等价行为（无门禁、无等待、无回滚）
drydock --precheck=false --health-gate=false --snapshot=false --rollback-on-unhealthy=false

# 严格环境：未知 tag 也阻断 + 强制 HEALTHCHECK
drydock --precheck-unknown-tag=block --require-healthcheck
```

启动期校验兜底：非法 unknown-tag 策略（退出码 2）、负 keep、非正 timeout、"关快照开回滚"等非法组合均在启动时失败退出，不留运行期意外（CHANGELOG.md「启动期校验」）。

---

## 5. 验证结果（本次交付会话实测）

环境：Git Bash，`cd /d/github/drydock`，`PATH=/d/github/.tools/go/bin:$PATH`，按任务书原命令执行：

| # | 检查 | 命令 | 退出码 | 结果 |
|---|---|---|---|---|
| 1 | 构建 | `go build ./...` | **0** | 通过 |
| 2 | 静态检查 | `go vet ./...` | **0** | 通过 |
| 3 | 全量测试 | `go test ./...` | **0** | **17 个包全部 `ok`**（`grep -c "^ok"` = 17） |

三项门禁退出码 **0 / 0 / 0**（0=通过；本次无未运行项，故无 -1）。为排除缓存干扰，另执行了强制重跑 `go test -count=1 ./...`：退出码仍为 **0**、17 个包全部 `ok`——测试结论不依赖构建缓存。

补充冒烟：`go run . --help` 退出码 0，二进制可正常启动并列出用法。

---

## 6. 评审结论：P0/P1 已清零

2026-09-22 评审修复 pass 结论（任务书与 `CHANGELOG.md`「安全加固（2026-09-22 评审修复）」段记录）：**全部 5 条 P0/P1 均成立并已修复，无反驳项**。修复证据本次逐一在代码中核实：

| # | P0/P1 修复项 | 核实证据 |
|---|---|---|
| 1 | 回滚按**不可变镜像 ID**创建，而非同名 tag（防 tag 已被重 pull 指向失败/被投毒新镜像） | 回归测试 `TestRestorerRollbackPinsImageIDNotTag`：`pkg/rollback/rollback_test.go:1107-1115` |
| 2 | 新增 `--health-gate` 总开关；`--rollback-on-unhealthy=true` 强制要求 `--health-gate`+`--snapshot` 同开，否则启动退出 | 旗标 `internal/flags/flags.go:248-251,283-286`；文档 `docs/arguments.md:555,584-587` |
| 3 | registry 认证链路加固：受限 HTTP client（30s 超时、≤3 跳仅同 host https 重定向、1MiB 响应上限）、realm 强制 https 且拒环回/私有地址 | `pkg/registry/auth/hardening_test.go` 存在并随 `go test` 通过；digest HEAD client 补 30s 超时 |
| 4 | 快照环境变量脱敏 `--snapshot-redact-env`（0600 sidecar 存真实值、读取回填）；`--snapshot-keep` 默认 3→1 收敛敏感数据滞留 | 旗标 `flags.go:258-261,517,522`；文档 `docs/arguments.md:516,532` |
| 5 | NOTICE 补 Apache-2.0 §4(b) 上游修改声明（module 更名、二进制更名、安全环与认证加固） | `NOTICE:12-16` 本次逐行读取核实 |

说明（诚实边界）：5 条 P0/P1 的**原始评审意见清单**未以独立文件形式存在于仓库中（`.mimosa/finding-ledger` 台账仅存 1 条 hook 拦截事件，指向 digest HEAD 的 TLS 问题，即 FOLLOWUPS #1）；上表结论以任务书声明 + CHANGELOG 修复记录为据，且每条的修复代码/测试/文档证据本次均已实地核实。评审期另识别出 **10 条 P2 遗留项**，逐条记录于 `FOLLOWUPS.md`，均不阻塞 v0.1。

---

## 7. 未覆盖与诚实声明

以下事项**本次未做或能力有限**，不夸大：

1. **未在真实 docker daemon 上端到端运行**。本次交付会话未执行任何 `docker` 命令（无 docker 环境可用性证据）；预检→快照→门禁→回滚全链路仅在单测层验证（mock container client）。真实宿主机上的完整更新-回滚演练尚未做过。
2. **changelog 预检对非 GitHub registry 覆盖有限**。v0.1 预检只消费目标镜像**内嵌 OCI 标签**（`org.opencontainers.image.source/description/version`），不做任何网络 changelog/破坏性变更取证——镜像没打这些标签就没有 changelog 证据。网络取证列为 v0.2（CHANGELOG「计划中」；FOLLOWUPS #9 已给出复用加固 HTTP client 的实现路径）。
3. **CLI 措辞仍是 watchtower**。`go run . --help` 实测显示 "Watchtower automatically updates…"、"Usage: watchtower"——`cmd/root.go` 的 `Use: "watchtower"` 刻意保留（MIGRATION.md 条目 6 声明为过渡期行为，FOLLOWUPS #7 列为 P2）。
4. **digest HEAD client 保留 `InsecureSkipVerify: true`**（继承自上游，自签名 registry 用户依赖；FOLLOWUPS #1，本次修复仅补了超时，TLS 姿态刻意未动）。
5. `go test ./...` 首次输出多数包显示 `(cached)`（结果来自本机更早运行的构建缓存且输入未变）；已用 `-count=1` 强制重跑复核，结论一致。仓库当前**不是 git 仓库**（`git log` 失败），无提交历史可查——版本事实以 CHANGELOG 为准。
6. 官方镜像未发布（v0.1 需源码构建，MIGRATION.md 开头声明）；`oryxBuildBinary`（约 20MB）为工作区遗留构建产物，非本次交付物。

---

## 8. 后续路线

对齐调研文件（2.2⑦ 缝隙"更新前读 changelog/破坏性变更预判"与横向结论"闭环最后一步"）与 CHANGELOG「计划中」/FOLLOWUPS：

1. **v0.2 预检网络取证（最高优先）**：拉取 GitHub Releases/CHANGEGRAM 类 changelog 并做破坏性变更预判，补齐 2.2⑦ 点名的"读 changelog"半环——复用 `pkg/registry/auth` 已加固的受限 HTTP client 模式（超时、同 host https 重定向、LimitReader、纯文本渲染，杜绝 HTML 注入通知，FOLLOWUPS #9）。
2. **快照整卷加密**（`--snapshot-encrypt`，FOLLOWUPS #5）与孤儿 sidecar 启动清扫（#6），进一步收敛敏感数据滞留。
3. **门禁增强**：Docker 事件流订阅、`RestartCount` 监控、自定义探针命令；每容器健康超时标签覆盖（#8：`com.drydock.updater.health-timeout=180s`）。
4. **registry TLS 姿态可配置化**：`--registry-tls-skip-verify`（默认 false）或每 registry CA 配置（#1）；realm 主机 DNS rebinding 防护（#2）与严格环境 realm 白名单 `DRYDOCK_REALM_ALLOWLIST`（#3）。
5. **回滚按 digest 重拉兜底**（#10）：旧镜像被清时用快照 `RepoDigests` 构造 `repo@sha256:…` 重拉，替代直接放弃。
6. **发布工程**：官方多架构镜像、goreleaser 镜像名去 containrrr 化、CLI/自身容器标签去 watchtower 化（#7，带弃用窗口）——为接盘 watchtower 用户群（调研 1.3"自托管更新管理刚需仍在"）提供零成本迁移面。

---

*本报告由交付核查于 2026-09-22 生成；§5 所有退出码为当日实测，§7 为如实声明的边界。*
