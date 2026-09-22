# Changelog

本项目的所有显著变更都会记录在此文件中。

格式基于 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，
版本管理遵循 [Semantic Versioning](https://semver.org/lang/zh-CN/)。

## [Unreleased]

### 安全加固（2026-09-22 评审修复）

- **回滚按不可变镜像 ID 创建**：`pkg/rollback/restore.go` 第 5 步改用快照钉住的本地镜像 ID（`sha256:...`）而非 tag 引用创建容器。回滚发生时同名 tag（如 `app:latest`）已被更新流程重新 pull 指向新镜像，按 tag 创建会原样重启刚失败（或被投毒）的新镜像；按 ID 创建保证"存在性校验查验的镜像"与"实际运行的镜像"逐字节一致。新增回归测试 `TestRestorerRollbackPinsImageIDNotTag`。
- **新增 `--health-gate`**（默认 `true`，`DRYDOCK_HEALTH_GATE`）：健康门禁可整体关闭，`--precheck=false --health-gate=false --snapshot=false --rollback-on-unhealthy=false` 即可完全还原 watchtower 等价行为；`--rollback-on-unhealthy=true` 现要求 `--health-gate` 与 `--snapshot` 同时开启，否则启动即退出。
- **registry 认证链路加固**（`pkg/registry/auth`）：统一受限 HTTP client——30s 超时、最多 3 跳且仅限同 host 的 https 重定向（防凭证外送/SSRF）、token 响应 1MiB 读取上限（防 OOM）、非 2xx 拒收；`WWW-Authenticate` realm 强制 https 且拒绝 localhost/环回/私有/保留地址（操作者自指的 registry 主机除外）。`pkg/registry/digest` 的 HEAD client 补 30s 整体超时。新增 `hardening_test.go` 覆盖 realm 校验与重定向策略。
- **快照环境变量脱敏**：新增 `--snapshot-redact-env`（默认 `true`，`DRYDOCK_SNAPSHOT_REDACT_ENV`），快照 JSON 中环境变量值替换为 `<drydock-redacted>` 占位符（键名保留），真实值写入同目录独立 `0600` sidecar 文件（`<快照ID>.env`），读取快照时自动回填，回滚能力不受影响；修剪时 sidecar 随快照一并删除。`--snapshot-keep` 默认值 3 → 1，减少敏感数据滞留。关闭脱敏时启动日志明确告警明文风险。
- **NOTICE**：补充 Apache-2.0 §4(b) 要求的上游源码修改声明（module 重命名、二进制更名、安全环与认证加固）。
- 遗留 P2 事项整理至 `FOLLOWUPS.md`（digest HEAD 的 `InsecureSkipVerify` 可配置化、realm DNS rebinding 防护、FailedLogs 进报告、快照整卷加密等 10 项）。

### 计划中

- 预检阶段的 changelog / 破坏性变更网络取证（v0.1 仅消费镜像内嵌 OCI 标签）。
- 健康门禁增强：Docker 事件流订阅、`RestartCount` 监控、自定义探针命令。
- 可自定义的周期报告模板。
- 官方多架构镜像发布与 goreleaser 镜像名去 containrrr 化。
- CLI 措辞与自身容器标签去 watchtower 化。

## [0.1.0] - 2026-09-22

首个发布版本：在 containrrr/watchtower 代码基之上落地"监控 → 拉新镜像 → 重建容器"之外的**安全闭环**。

### 新增

- **预检（`pkg/precheck`）**：更新前策略门——semver 跨大版本阻断（降级放行并标注）、预发布 tag 阻断、非 semver tag 的 `allow`/`block` 策略、`--require-healthcheck` 强制；目标镜像 OCI 标签作为 changelog 证据进入报告；支持 `com.drydock.updater.precheck` 容器标签单容器豁免。
- **快照（`pkg/rollback` 的 `FileSnapshotStore`）**：更新前对容器 inspect 深拷贝并原子落盘（`<容器名>-<unixnano>.json`），按容器名组织，Drydock 重启后仍可用；`--snapshot-keep` 控制每容器保留数。
- **健康门禁（`pkg/healthgate`）**：新容器启动后轮询健康状态——有 `HEALTHCHECK` 等到 `healthy` 放行、`unhealthy`/退出即失败、窗口耗尽报超时；无 `HEALTHCHECK` 退化为运行态单次确认；轮询间隔收敛到 `[100ms, timeout/2]` 保证至少两次探测。
- **自动回滚（`pkg/rollback` 的 `Restorer`）**：门禁失败时按快照原样重建旧容器（原镜像、配置、网络、原名）；失败新容器改名 `drydock-failed-<name>-<时间戳>` 保留并截取最后 50 行日志；旧镜像缺失时报 `ErrRollbackImageMissing`；创建/启动期失败会尽力复活失败容器避免双重停机。
- **周期报告（`pkg/updatereport`）**：每容器 `NAME / STATUS / IMAGE / PRECHECK / HEALTH / ROLLBACK / ERROR` 一行的周期汇总，控制台始终输出，配置 `--notification-url` 时经 shoutrrr 推送；安静周期（无 `updated`/`failed`/`rolled-back`）不推送。
- **共享契约（`pkg/safeflow`）**：`Prechecker` / `Snapshotter` / `HealthGater` / `Rollbacker` 接口与 `CycleReport` 报告类型；四个功能包互不依赖，组合只发生在 `cmd` 层。
- **11 个安全环旗标**（均含 `DRYDOCK_*` 环境变量）：`--precheck`（默认 `true`）、`--block-major`（`true`）、`--block-prerelease`（`true`）、`--precheck-unknown-tag`（`allow`）、`--require-healthcheck`（`false`）、`--snapshot`（`true`）、`--snapshot-dir`（`/var/lib/drydock/snapshots`）、`--snapshot-keep`（`3`）、`--health-timeout`（`60s`）、`--health-interval`（`5s`）、`--rollback-on-unhealthy`（`true`）。
- **启动期校验**：非法取值/组合（非法 unknown-tag 策略、负的 keep、非正 timeout、关快照开回滚、快照目录不可写）在启动时失败退出，不留运行期意外；`--precheck-unknown-tag` 非法值退出码为 2。

### 变更

- 仓库由 containrrr/watchtower 迁移为 **drydock-updater/drydock**：module path 改为 `github.com/drydock-updater/drydock`，构建产物更名为 `drydock`；许可保持 Apache-2.0，衍生声明见 `NOTICE`。

### 兼容性

- watchtower 全部命令行旗标、`WATCHTOWER_*` 环境变量与 `com.centurylinklabs.watchtower.*` 容器标签保留，语义不变。
- `--precheck=false` 可完全退回 watchtower 等价更新行为（快照/门禁/回滚仍由各自旗标控制）。
- 默认行为差异：semver 跨大版本与预发布 tag 的容器默认被跳过（`skipped`）而非直接更新；不健康更新默认被自动回滚。详见 `MIGRATION.md`。

[Unreleased]: https://github.com/drydock-updater/drydock/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/drydock-updater/drydock/releases/tag/v0.1.0
