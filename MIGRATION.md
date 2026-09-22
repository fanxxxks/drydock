# 从 containrrr/watchtower 迁移到 Drydock

本文面向现有 containrrr/watchtower 用户。结论先行：**所有 watchtower 旗标、`WATCHTOWER_*` 环境变量与容器标签都原样保留**，迁移只需换二进制/镜像；默认多出来的安全环行为如不需要，一条旗标即可退回。

> v0.1 尚未发布官方镜像，暂需从源码构建（见 [README 快速上手](README.md#快速上手)）。

## compose 片段对照

### 迁移前：watchtower

```yaml
services:
  watchtower:
    image: containrrr/watchtower
    container_name: watchtower
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
    environment:
      - WATCHTOWER_SCHEDULE=0 0 4 * * *
      - WATCHTOWER_CLEANUP=true
    restart: unless-stopped
```

### 迁移后：Drydock（等价行为，安全环保持默认）

```yaml
services:
  drydock:
    build:
      context: ./drydock            # Drydock 仓库
      dockerfile: dockerfiles/Dockerfile
    container_name: drydock
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
      - drydock-snapshots:/var/lib/drydock/snapshots   # 新增：快照持久化
    environment:
      - WATCHTOWER_SCHEDULE=0 0 4 * * *                # 原样保留
      - WATCHTOWER_CLEANUP=true                        # 原样保留
    restart: unless-stopped

volumes:
  drydock-snapshots:
```

变化只有两处：

1. **换镜像/二进制**——调度、清理、通知等配置一个字都不用改；
2. **建议加一个快照卷**——默认快照目录是 `/var/lib/drydock/snapshots`。不挂载卷也能运行（目录在容器内自动创建），但 Drydock 容器自身重建后历史快照会丢失，回滚保护因此打了折扣。

### 迁移后：完全复刻 watchtower 行为（关闭安全环）

```yaml
services:
  drydock:
    build:
      context: ./drydock
      dockerfile: dockerfiles/Dockerfile
    container_name: drydock
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
    environment:
      - WATCHTOWER_SCHEDULE=0 0 4 * * *
      - WATCHTOWER_CLEANUP=true
      - DRYDOCK_PRECHECK=false          # 关预检
      - DRYDOCK_SNAPSHOT=false          # 关快照（此时必须同时关回滚）
      - DRYDOCK_ROLLBACK_ON_UNHEALTHY=false
    restart: unless-stopped
```

注意：`DRYDOCK_SNAPSHOT=false` 与 `DRYDOCK_ROLLBACK_ON_UNHEALTHY=true` 的组合会在**启动时**被拒绝（快照是回滚的依托）。健康门禁没有总开关旗标——它与 Docker API 客户端同生（详见[行为差异](#行为差异)第 4 条）。

## 旗标兼容表

### watchtower 旗标 → Drydock 行为

以下旗标**全部保留，名称与语义不变**（`internal/flags/flags.go` 中的注册与上游一致）：

| 类别 | 旗标 | Drydock 行为 |
|---|---|---|
| 调度 | `--interval` / `-i`、`--schedule` / `-s`、`--run-once` / `-R` | 不变。二者仍互斥，只能设一个 |
| 容器选择 | `--label-enable` / `-e`、`--disable-containers` / `-x`、`--scope`、位置参数（容器名列表） | 不变 |
| 更新行为 | `--no-pull`、`--no-restart`、`--cleanup` / `-c`、`--remove-volumes`、`--include-stopped` / `-S`、`--include-restarting`、`--revive-stopped`、`--rolling-restart`、`--monitor-only` / `-m`、`--stop-timeout` / `-t` | 不变。`--stop-timeout` 同时作为回滚阶段停止失败容器的优雅窗口 |
| 生命周期钩子 | `--enable-lifecycle-hooks`（及 `com.centurylinklabs.watchtower.lifecycle.*` 标签、退出码 75 跳过语义） | 不变 |
| Docker 连接 | `--host` / `-H`、`--tlsverify` / `-v`、`--api-version` / `-a` | 不变 |
| 通知 | `--notifications` / `-n`、`--notification-url`、email / slack / msteams / gotify 全系列 | 不变。`--notification-url` 现在还额外承担安全环周期报告的推送 |
| HTTP API | `--http-api-update`、`--http-api-metrics`、`--http-api-token`、`--http-api-periodic-polls` | 不变 |
| 日志 | `--debug` / `-d`、`--trace`、`--log-level`、`--log-format` / `-l`、`--no-color` | 不变 |
| 输出 | `--porcelain` / `-P`、`--no-startup-message` | 不变 |

### 新增旗标（watchtower 没有）

| 旗标 | 默认值 | 环境变量 | 作用 |
|---|---|---|---|
| `--precheck` | `true` | `DRYDOCK_PRECHECK` | 预检总开关；`false` 退回 watchtower 等价行为 |
| `--block-major` | `true` | `DRYDOCK_BLOCK_MAJOR` | semver 跨大版本阻断；降级不阻断 |
| `--block-prerelease` | `true` | `DRYDOCK_BLOCK_PRERELEASE` | 目标 tag 含 `-prerelease` 段阻断 |
| `--precheck-unknown-tag` | `allow` | `DRYDOCK_PRECHECK_UNKNOWN_TAG` | 非 semver tag 策略：`allow` / `block`；非法值启动退出（exit 2） |
| `--require-healthcheck` | `false` | `DRYDOCK_REQUIRE_HEALTHCHECK` | 目标镜像无 `HEALTHCHECK` 则预检阻断 |
| `--snapshot` | `true` | `DRYDOCK_SNAPSHOT` | 更新前快照；`false` 时不得开启回滚 |
| `--snapshot-redact-env` | `true` | `DRYDOCK_SNAPSHOT_REDACT_ENV` | 快照文件中环境变量值脱敏，真实值存独立 `0600` sidecar 文件；`false` = 明文（含 secrets） |
| `--snapshot-dir` | `/var/lib/drydock/snapshots` | `DRYDOCK_SNAPSHOT_DIR` | 快照目录，启动时创建，不可写即启动失败 |
| `--snapshot-keep` | `1` | `DRYDOCK_SNAPSHOT_KEEP` | 每容器保留快照数；`0` = 成功后清理；负值启动报错 |
| `--health-gate` | `true` | `DRYDOCK_HEALTH_GATE` | 门禁总开关；`false` 时不等待健康检查（更接近 watchtower 行为），且不得开启回滚 |
| `--health-timeout` | `60s` | `DRYDOCK_HEALTH_TIMEOUT` | 门禁窗口上限；`<=0` 启动报错 |
| `--health-interval` | `5s` | `DRYDOCK_HEALTH_INTERVAL` | 门禁轮询间隔；收敛到 `[100ms, timeout/2]` |
| `--rollback-on-unhealthy` | `true` | `DRYDOCK_ROLLBACK_ON_UNHEALTHY` | 门禁失败自动回滚；`false` 只标记失败、旧镜像仍不清理 |

## 环境变量对照

- **`WATCHTOWER_*` 全部继续有效**（含 `WATCHTOWER_POLL_INTERVAL`、`WATCHTOWER_SCHEDULE`、`WATCHTOWER_TIMEOUT`、`WATCHTOWER_NOTIFICATION_URL` 等），优先级规则与上游一致：命令行旗标 > 环境变量 > 默认值。
- 安全环新增 `DRYDOCK_*` 系列（见上表），与 `WATCHTOWER_*` 互不干扰，可以混用。

## 容器标签对照

| 标签 | 状态 |
|---|---|
| `com.centurylinklabs.watchtower.enable` / `.enable-true` / `.enable-false` | 保留，语义不变 |
| `com.centurylinklabs.watchtower.monitor-only` | 保留，语义不变 |
| `com.centurylinklabs.watchtower.depends-on` | 保留，语义不变 |
| `com.centurylinklabs.watchtower.stop-signal` | 保留，语义不变 |
| `com.centurylinklabs.watchtower.scope` | 保留，语义不变 |
| `com.centurylinklabs.watchtower.lifecycle.pre-check` / `.post-check` | 保留，语义不变 |
| `com.drydock.updater.precheck` | **新增**。设为 `false`（可被 `strconv.ParseBool` 解析为假的值均可，如 `0`、`f`）即对该容器绕过预检门 |

## 行为差异

默认配置下（安全环全开），Drydock 与 watchtower 的实际行为差异有且只有以下几条：

1. **semver 跨大版本默认跳过。** 运行 `nginx:1.25` 而新 tag 是 `3.0` 的容器，watchtower 会直接更新；Drydock 默认记为 `skipped`，理由 `blocked-major`。需要放行时用 `--block-major=false` 或单容器标签豁免。
2. **预发布 tag 默认跳过。** 目标 tag 是 `1.10.0-beta.1`、`rc.1` 这类时默认 `skipped`（`blocked-prerelease`）。跟 `latest` 走的用户不受影响——`latest` 不是 semver，默认策略是 `allow`，行为与 watchtower 一致。
3. **不健康更新会被自动回滚。** watchtower 重建完就宣告成功；Drydock 会先过健康门禁（见下条），失败则按更新前快照原样重建旧容器，服务回到更新前状态。失败的新容器改名 `drydock-failed-<name>-<时间戳>` 保留取证，需要手动清理。回滚对 Drydock 自身容器不生效（v0.1 不支持自回滚）。
4. **每次重建后多了至多 60s 的门禁等待。** 有 `HEALTHCHECK` 的镜像等到 `healthy`（或 `unhealthy`/超时）为止；没有 `HEALTHCHECK` 的镜像退化为"运行态单次确认"——起来就过，基本无感。这会拉长大批量更新的总时长，可用 `--health-timeout` 收紧。
5. **启动校验更严格。** 非法旗标组合/取值（如 `--precheck-unknown-tag=sometimes`、`--snapshot-keep=-1`、`--health-timeout=0`、`--snapshot=false` 或 `--health-gate=false` 且开回滚）在启动时即失败退出，而不是运行期才出意外。`--precheck-unknown-tag` 的非法值退出码为 2，其余为 1。
6. **外观遗留。** v0.1 的 CLI 用法串与启动日志仍自称 `watchtower`（如 `Watchtower v0.1.0`），自身容器仍打 `com.centurylinklabs.watchtower` 标签——这是刻意的兼容保留，将按[路线图](README.md#路线图)逐步更名，不影响功能。

另有一点交互值得知道：`--cleanup` 与回滚是安全的——门禁在镜像清理**之前**执行，只有通过了门禁的容器其旧镜像才会进入清理集合；被回滚的容器旧镜像绝不会在其还依赖时被删除。

## 常见问题

**问：我已经用 watchtower 的 `--label-enable` 只监控白名单容器，迁移后预检会干扰白名单吗？**

不会。预检发生在容器已被判定"过期、待更新"之后，白名单外的容器根本不会走到这一步。

**问：我的镜像都用 `latest` tag，安全环对我意味着什么？**

预检的 semver 规则不适用（未知 tag 默认 `allow`），快照、门禁、回滚照常生效。也就是说：`latest` 用户拿到的净收益是"起不来就自动回滚"，而非版本门槛。

**问：调度方式要改吗？**

不用。`WATCHTOWER_SCHEDULE`（cron 表达式）与 `WATCHTOWER_POLL_INTERVAL`（秒）原样支持，仍二选一。

**问：drydock-failed-* 取证容器会一直堆着吗？**

会，v0.1 有意保留现场、不做自动删除。确认无用后 `docker rm` 掉即可；其最后 50 行日志也已包含在周期报告里。
