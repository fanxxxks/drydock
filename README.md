# Drydock

**Drydock**（干船坞）是 [containrrr/watchtower](https://github.com/containrrr/watchtower) 的继任者——一个带**安全闭环**的 Docker 容器自动更新器。

watchtower 已停更两年以上（[containrrr/watchtower#2067](https://github.com/containrrr/watchtower/issues/2067)），社区尚无成熟接盘 fork；现有替代品（如 WUD）只做"监控 + 白名单"。Drydock 在 watchtower 十年验证过的"监控 → 拉新镜像 → 重建容器"核心循环之上，补齐自托管用户真正缺失的一环：**更新出问题时，自动发现、自动止损**。

```
更新前预检（预发布/跨大版本/语义版本门槛）
    → 更新前快照
    → 更新（拉取镜像 → 优雅停止 → 重建容器）
    → 健康门禁
    → 不健康自动回滚
```

## 为什么 Drydock 更安全

自托管社区对自动更新的最大顾虑是破坏性变更（"Too scared to upgrade"是每周都出现的帖子）。watchtower 式"拉到就换"的更新器因此被视为危险。Drydock 用四根支柱把"自动更新"变成"有安全网的自动更新"：

### 1. 预检（Precheck）—— 把坏更新挡在门外

在容器被停止**之前**，对每个待更新容器做策略评估（`--precheck`，默认开启）：

- **跨大版本阻断**（`--block-major`，默认开）：当前与目标 tag 均可解析为 semver 且 major 升高时跳过更新（对应上游 [watchtower#216](https://github.com/containrrr/watchtower/issues/216) 的 semver 感知诉求）；**降级不阻断**（运维主动钉回坏版本是合法操作，会在报告中标注）。
- **预发布阻断**（`--block-prerelease`，默认开）：目标 tag 含 `-prerelease` 段（如 `1.10.0-beta.1`、`rc.1`）时跳过。
- **未知 tag 策略**（`--precheck-unknown-tag`，默认 `allow`）：`latest`、日期 tag、digest-pin 等无法解析为 semver 的场景，可选择 `allow`（保持 watchtower 等价行为）或 `block`（严格环境）。
- **HEALTHCHECK 强制**（`--require-healthcheck`，默认关）：目标镜像未定义 `HEALTHCHECK`（或 `test` 为 `["NONE"]`）时直接阻断。
- 目标镜像的 OCI 标签（`org.opencontainers.image.source` / `description` / `version` 等）作为 changelog 证据附在报告里——预检只用本地数据，不产生额外的 registry 请求。
- 单容器豁免：给容器打标签 `com.drydock.updater.precheck=false` 即可绕过整个策略门。

被预检否决的容器在本周期内**完全不被触碰**，报告状态为 `skipped`。

### 2. 快照（Snapshot）—— 留下还原点

任何容器被停止之前，Drydock 对其 `docker inspect` 结果做**深拷贝**并原子落盘（`--snapshot`，默认开启；`--snapshot-dir` 默认 `/var/lib/drydock/snapshots`；`--snapshot-keep` 默认保留每容器最近 1 份，成功更新后自动清理）。深拷贝是必须的：重建流程会在原地改写 inspect 数据，快照必须冻结改动之前的原始状态。快照按容器**名字**（而非会随重建变化的 ID）组织，Drydock 重启后仍可用于回滚。

**敏感信息处理**：快照包含容器的完整环境变量。默认 `--snapshot-redact-env=true` 会把快照文件里的环境变量**值**替换为占位符，真实值写入同目录下独立的 `0600` sidecar 文件（`<快照ID>.env`），读取快照时自动回填；快照目录 `0700`、文件 `0600`。若显式关闭脱敏，快照文件将以**明文**包含全部环境变量（含 `POSTGRES_PASSWORD`、API token 等 secrets），请确保快照目录位于加密/tmpfs 卷并缩短保留期。

### 3. 健康门禁（Health gate）—— 上线前先体检

新容器启动后，Drydock 不会立刻宣布成功，而是轮询其健康状态（`--health-timeout` 默认 60s，`--health-interval` 默认 5s，实际收敛到 `[100ms, timeout/2]` 保证至少两次探测）：

- 镜像定义了 `HEALTHCHECK`：等到 `healthy` 才放行；`unhealthy` 或容器退出立即判失败；
- 镜像没有 `HEALTHCHECK`：退化为"运行态单次确认"——容器在运行即通过，没起来立即判失败；
- 窗口耗尽仍未有结论：判超时失败。

门禁在镜像清理**之前**执行，因此不健康的更新绝不会有旧镜像被从脚下删掉。

### 4. 回滚（Rollback）—— 出事自动止损

门禁判失败且 `--rollback-on-unhealthy`（默认开）时，Drydock 按快照原样重建旧容器：原镜像、原配置、原网络、原名。失败的新容器不会被销毁，而是改名 `drydock-failed-<name>-<unixnano>` 并截取最后 50 行日志留作取证。回滚成功后容器状态为 `rolled-back`，服务恢复到更新前版本。

## 快速上手

> v0.1 尚未发布官方镜像，请从源码构建（参见[路线图](#路线图)）。

### 从源码运行（最快）

```sh
git clone https://github.com/drydock-updater/drydock.git
cd drydock
go build .                    # 产出二进制 drydock
./drydock --run-once          # 扫描全部容器，跑一轮安全更新后退出
```

### 作为常驻容器运行

```sh
docker build -f dockerfiles/Dockerfile -t drydock:local .
docker run -d \
  --name drydock \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v drydock-snapshots:/var/lib/drydock/snapshots \
  drydock:local
```

挂载 `/var/run/docker.sock` 是必须的；`drydock-snapshots` 卷用于持久化快照（不挂载也能跑，但 Drydock 容器自身重建后历史快照会丢失）。

### docker-compose.yml

```yaml
services:
  drydock:
    build:
      context: ./drydock            # 本仓库
      dockerfile: dockerfiles/Dockerfile
    container_name: drydock
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
      - drydock-snapshots:/var/lib/drydock/snapshots
    environment:
      - WATCHTOWER_SCHEDULE=0 0 4 * * *   # 每天凌晨 4 点检查更新
      - WATCHTOWER_CLEANUP=true           # 更新成功后清理旧镜像

volumes:
  drydock-snapshots:
```

### 只监控个别容器

与 watchtower 相同，把容器名作为参数传入即可只监控它们：

```sh
./drydock nginx redis
```

## 安全环旗标速查

以下旗标均可通过同名语义的环境变量覆盖（表末列）。完整旗标列表见 [docs/arguments.md](docs/arguments.md)。

| 旗标 | 默认值 | 环境变量 | 作用 |
|---|---|---|---|
| `--precheck` | `true` | `DRYDOCK_PRECHECK` | 预检总开关。`false` = 退回 watchtower 等价行为 |
| `--block-major` | `true` | `DRYDOCK_BLOCK_MAJOR` | semver 跨大版本时阻断；降级不阻断 |
| `--block-prerelease` | `true` | `DRYDOCK_BLOCK_PRERELEASE` | 目标 tag 含 `-prerelease` 段时阻断 |
| `--precheck-unknown-tag` | `allow` | `DRYDOCK_PRECHECK_UNKNOWN_TAG` | 非 semver tag 的策略：`allow` / `block`（非法值启动即退出，exit 2） |
| `--require-healthcheck` | `false` | `DRYDOCK_REQUIRE_HEALTHCHECK` | 目标镜像无 `HEALTHCHECK` 则在预检阶段阻断 |
| `--snapshot` | `true` | `DRYDOCK_SNAPSHOT` | 更新前快照。`false` 时不可同时开 `--rollback-on-unhealthy` |
| `--snapshot-redact-env` | `true` | `DRYDOCK_SNAPSHOT_REDACT_ENV` | 快照文件中环境变量值脱敏为占位符，真实值存 `0600` sidecar 文件；`false` = 明文落盘（含 secrets，自担风险） |
| `--snapshot-dir` | `/var/lib/drydock/snapshots` | `DRYDOCK_SNAPSHOT_DIR` | 快照 JSON 目录，启动时创建；不可写则启动失败 |
| `--snapshot-keep` | `1` | `DRYDOCK_SNAPSHOT_KEEP` | 每容器保留快照数；`0` = 成功后即清理；负值启动报错 |
| `--health-gate` | `true` | `DRYDOCK_HEALTH_GATE` | 健康门禁总开关。`false` = 不等待健康检查（退回 watchtower 等价行为）；关闭时不可同时开 `--rollback-on-unhealthy` |
| `--health-timeout` | `60s` | `DRYDOCK_HEALTH_TIMEOUT` | 健康门禁窗口上限；`<=0` 启动报错 |
| `--health-interval` | `5s` | `DRYDOCK_HEALTH_INTERVAL` | 门禁轮询间隔；收敛到 `[100ms, timeout/2]` |
| `--rollback-on-unhealthy` | `true` | `DRYDOCK_ROLLBACK_ON_UNHEALTHY` | 门禁失败时按快照回滚；`false` = 只标记失败、留新容器人工处置 |

非法组合（如 `--snapshot=false` 且 `--rollback-on-unhealthy=true`）与非法取值在**启动时**报错退出，绝不留到运行期爆炸。每轮更新的结局（`updated` / `skipped` / `failed` / `rolled-back` / `fresh`）汇总为周期报告，输出到控制台；配置了 `--notification-url`（shoutrrr）时同时推送。

## 与 watchtower 的兼容性

Drydock 由 watchtower 代码库直接演进而来，目标是**迁移成本趋近于零**：

- **命令行旗标全部保留**：`--interval` / `--schedule` / `--run-once` / `--cleanup` / `--label-enable` / `--scope` / `--rolling-restart` / 生命周期钩子 / 通知 / HTTP API 等旗标名称与语义不变。
- **`WATCHTOWER_*` 环境变量继续有效**：安全环旗标使用新的 `DRYDOCK_*` 前缀，两套互不干扰。
- **容器标签兼容**：`com.centurylinklabs.watchtower.enable` / `.enable-true` / `.monitor-only` / `.depends-on` / `.stop-signal` 等标签原样识别；新增 `com.drydock.updater.precheck` 单容器豁免预检。
- **调度、容器选择、排序依赖重建、通知渠道（shoutrrr 全家桶）**等行为与 watchtower 一致。
- **默认行为差异**（安全环默认开启所致）：semver 跨大版本与预发布 tag 默认被跳过；每次重建后多了至多 60s 的门禁窗口；不健康更新会被自动回滚，失败现场以 `drydock-failed-*` 容器保留。传 `--precheck=false --health-gate=false --snapshot=false --rollback-on-unhealthy=false` 即可完全退回 watchtower 等价行为（门禁、快照、回滚逐级关闭，`--rollback-on-unhealthy` 依赖前两者）。

从 containrrr/watchtower 迁移的完整对照（compose 片段、旗标表、行为差异清单）见 **[MIGRATION.md](MIGRATION.md)**；安全更新机制逐阶段详解见 **[docs/safe-update.md](docs/safe-update.md)**。

## 路线图

**v0.1（当前）**——安全闭环落地：

- 四支柱：预检、快照、健康门禁、自动回滚（`pkg/precheck`、`pkg/rollback`、`pkg/healthgate`）
- 11 个 `DRYDOCK_*` 旗标与启动期校验
- 周期报告（`pkg/updatereport`）：每容器 NAME / STATUS / IMAGE / PRECHECK / HEALTH / ROLLBACK / ERROR 一行的汇总，控制台 + shoutrrr 推送

**v0.2 候选**（按代码中标注的非目标与已知欠账排序）：

- **changelog / 破坏性变更网络取证**：v0.1 预检只消费镜像内嵌的 OCI 标签，不做网络请求；接口已为网络取证预留扩展点。
- **门禁增强**：订阅 Docker 事件流替代轮询、监控 `RestartCount` 增长、自定义探针命令。
- **可自定义周期报告模板**（v0.1 只有内置单模板）。
- **官方多架构镜像发布**（当前 goreleaser 配置仍沿用上游 containrrr 镜像名，待更名）与 CI/CD 流水线。
- **去 watchtower 化**：CLI 用法串、启动日志与自身容器标签仍显示 `watchtower` 字样，将逐步更名。

## 溯源与许可

- 代码衍生自 [containrrr/watchtower](https://github.com/containrrr/watchtower) 及其贡献者，遵循 **Apache License 2.0**（见 [LICENSE.md](LICENSE.md)），衍生声明见 [NOTICE](NOTICE)。
- 安全环四个包（`pkg/precheck`、`pkg/rollback`、`pkg/healthgate`、`pkg/updatereport`）共享 `pkg/safeflow` 契约，互不依赖，组合只发生在 `cmd` 层。
