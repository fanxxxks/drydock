# 安全更新机制详解

本文逐阶段拆解 Drydock 的更新安全环：**预检 → 快照 → 更新 → 健康门禁 → 回滚**，给出每个阶段的判定条件、失败分支与最终落到周期报告上的状态。旗标名与默认值以 `internal/flags/flags.go` 的注册和 `cmd/root.go` 的组装为准。

## 总览

一个更新周期内，每个被监控的容器独立走完下面的流程，并落位于五个互斥状态之一（`pkg/safeflow/report.go`）：

| 状态 | 含义 |
|---|---|
| `fresh` | 已运行最新镜像，本周期无事可做 |
| `skipped` | 容器过期，但更新被预检否决（或经标签豁免、退出码 75 钩子等主动跳过），容器**完全未被触碰** |
| `updated` | 重建成功且通过健康门禁 |
| `failed` | 更新尝试出错（拉取/重建失败、门禁超时或不健康且未完成回滚） |
| `rolled-back` | 更新被门禁判负，且已按快照成功恢复旧容器 |

```
                 ┌──────────────────────────── 启动校验（一次性） ────────────────────────────┐
                 │ 旗标取值/组合非法 → 启动失败退出（见 §0），绝不带病运行                      │
                 └───────────────────────────────────────────────────────────────────────────┘
容器过期？
 ├─ 否 → fresh
 └─ 是 → 预检（--precheck）
      ├─ 否决 → skipped（容器不动）
      └─ 放行 → 快照（--snapshot）
           ├─ 失败 → 记错误、继续更新（本周期无还原点）
           └─ 成功 → 更新（停止 → 重建）
                ├─ 重建失败 → failed
                └─ 重建成功 → 健康门禁
                     ├─ 通过 → updated（按 --snapshot-keep 清理旧快照）
                     └─ 未通过 → 回滚（--rollback-on-unhealthy）
                          ├─ 回滚成功 → rolled-back
                          └─ 回滚失败/无快照 → failed（保留现场人工处置）
```

## 阶段 0：启动校验

安全环的全部非法配置在进程启动、任何容器被触碰**之前**检查（`cmd/root.go` 的 `buildSafetyLoop`）：

| 校验 | 失败行为 |
|---|---|
| `--precheck-unknown-tag` 不是 `allow`/`block` | 报错并 `exit 2`（对齐 cobra 用法错误的退出码约定） |
| `--snapshot-keep < 0` | fatal 退出 |
| `--health-timeout <= 0` | fatal 退出 |
| `--snapshot=false` 且 `--rollback-on-unhealthy=true` | fatal 退出（快照是回滚的唯一依托） |
| `--snapshot-dir` 无法 `MkdirAll` | fatal 退出 |
| `--health-interval < 100ms` 或 `> timeout/2` | 不失败：打 warn 并由门禁收敛（见 §4） |

设计意图：配置错误是运维错误而非运行期事故，应该在启动时暴露。

## 阶段 1：预检（precheck）

**位置**：容器已被判定过期（`IsContainerStale` 返回真、新镜像已拉取到本地）之后、容器被标记待更新之前（`internal/actions/update.go` 的过期扫描循环）。

**输入全部本地可得**：当前镜像 ref 来自运行容器的 inspect（`Config.Image`），目标镜像的标签与 HEALTHCHECK 来自刚拉取镜像的本地 inspect——预检不产生任何 registry 请求。目标镜像 inspect 失败时按"无标签、无 HEALTHCHECK"处理并打 warn，该降级只在 `--require-healthcheck` 下有实际影响。

**判定顺序**（`pkg/precheck/precheck.go`，首个命中即出结论）：

1. **单容器豁免**：容器标签 `com.drydock.updater.precheck` 的值可被 `strconv.ParseBool` 解析为假（`false`、`0`、`f`…）→ 直接放行，`reason=bypassed-by-label`。标签缺失或值不可解析则门继续有效。
2. **HEALTHCHECK 强制**（`--require-healthcheck=true` 且目标镜像无真实 HEALTHCHECK）→ 否决，`reason=blocked-no-healthcheck`。"真实"按 Docker 语义：`HEALTHCHECK` 缺失、为空，或 `test` 恰为 `["NONE"]` 都算没有。此项先于一切 tag 推理，是最硬的阻断。
3. **semver 判定表**：两侧 tag 均可解析为保守 semver 时——
   - 目标 major > 当前 major 且 `--block-major=true` → 否决，`reason=blocked-major`；
   - 目标 tag 含 `-prerelease` 段且 `--block-prerelease=true` → 否决，`reason=blocked-prerelease`；
   - 目标版本低于当前（降级）→ **放行**，但在报告中显式标注（运维钉回坏版本是合法操作）；
   - 其余 → 放行，`reason=allowed`。
4. **未知 tag 策略**：任一侧 tag 不可解析为 semver（`latest`、日期 tag、digest-pin、缺 tag）时，`--precheck-unknown-tag=block` → 否决（`reason=blocked-unknown-tag`，detail 会指明哪一侧无法解析）；`=allow`（默认）→ 放行。

无论结论如何，目标镜像的 OCI 证据标签（`org.opencontainers.image.source`、`.description`、`.changelog.url`、`.version`，按此优先级，至多 4 条）以 `notes` 形式附在裁决里——**notes 只是报告材料，永远不构成阻断理由**（v0.1 不做网络取证）。

**失败分支**：预检实现本身的错误也会否决该容器的更新（宁可不更新，不可未验证就更新），容器记 `skipped`。被否决的容器本周期完全不被触碰——不会被停止，也不会被计入待更新集合。

## 阶段 2：快照（snapshot）

**位置**：依赖排序完成之后、**任何容器被停止或滚动重启之前**（`internal/actions/update.go` 的 `takeSafetySnapshots`）。对每个将被动过的容器（含因链接关系被连带重启者）：

1. 取容器的活动 inspect 载荷并**深拷贝**——这一步是正确性关键：重建流程会在原地改写 inspect（剔除镜像默认值、改写 Links、删除容器 ID 短别名），快照必须冻结改动前的原始状态；
2. 校验载荷可还原（容器名、`Config`、`HostConfig`、镜像 ref、镜像 ID 齐全；不齐全报 `ErrSnapshotInvalid` 并**不落盘**）；
3. 以临时文件 + `os.Rename` 原子写入 `<snapshot-dir>/<容器名>-<unixnano>.json`。

快照按容器**名字**组织而非 ID——重建必然更换 ID，而名字跨重建稳定，这使得 Drydock 进程重启后仍能找到还原点。

**失败分支**：快照 I/O 失败**不会中止更新**——记一条错误日志后继续，代价是该容器本周期没有还原点（门禁失败时只能 `failed`，无法回滚）。原则：I/O 抖动不许让更新器瘫痪。

**敏感信息与脱敏**：快照含容器全部环境变量。默认 `--snapshot-redact-env=true` 将快照 JSON 中的环境变量**值**替换为 `<drydock-redacted>` 占位符（键名保留），真实值写入同目录独立 `0600` sidecar 文件（`<快照ID>.env`），`Latest` 读取时自动回填，回滚能力不受影响；快照目录 `0700`、快照与 sidecar 文件均 `0600`。关闭脱敏（`--snapshot-redact-env=false`）则快照文件**明文**含 secrets，需自担风险（建议 tmpfs/加密卷 + 缩短保留期）。

**保留策略**：`--snapshot-keep`（默认 1）。仅在**该容器通过门禁**后才执行修剪；`0` 表示成功后全部清理；失败/回滚的容器快照一律保留。修剪失败仅打 warn；修剪同时删除对应的 env sidecar，secret 载体不会孤儿化滞留。

## 阶段 3：更新（stop / recreate）

上游 watchtower 验证多年的路径，Drydock 不做改动：按依赖逆序优雅停止（`--stop-timeout`，默认 10s）、按正序以同一配置重建（含 watchtower 自身容器的特殊改名-先启-再停路径），滚动重启模式（`--rolling-restart`）同样被安全环包裹——逐台停止前照常快照、重建后逐台过门禁。

**失败分支**：拉取失败、配置校验失败、停止失败、重建失败 → 容器记 `failed`，错误进入周期报告；重建失败时旧容器不会被删。`--cleanup` 只清理**通过了门禁**的容器的旧镜像——回滚容器的旧镜像绝不会在其仍被依赖时进入清理集合。

## 阶段 4：健康门禁（health gate）

**位置**：新容器 `StartContainer` 返回之后、post-update 钩子与镜像清理之前（`internal/actions/update.go` 的 `gateReplacement`）。门禁是**纯观察者**：只轮询 inspect，绝不重启或改动容器。它在清理之前阻塞执行，正是不健康更新的旧镜像不被从脚下删掉的保证。

**参数收敛**（`normalizeOptions`）：`--health-interval` 被夹到 `[100ms, --health-timeout/2]`（窗口极小时下限随之上调），保证任何窗口至少容纳两次探测；`--health-timeout`、`--health-interval` 的默认值分别为 60s、5s。启动时若传入值会被收敛，会打 warn 指明实际生效值。

**判定表**（每次探测按序求值，首个命中即返回）：

| 观察到 | 结论 |
|---|---|
| 容器已消失（inspect 报 NotFound） | 立即失败，`ErrUnhealthy`，reason="container gone" |
| 镜像无 HEALTHCHECK 且容器在运行 | **立即通过**（单次探测即定，不等窗口耗尽），status=`unknown`，reason="no HEALTHCHECK defined; container running" |
| 镜像无 HEALTHCHECK 且容器未运行 | 立即失败，`ErrUnhealthy`，status=`exited`，携带退出码 |
| 镜像有 HEALTHCHECK，容器已退出 | 立即失败（退出优先于健康状态——退出的容器不会再转健康），status=`exited`，携带退出码 |
| 健康状态 `healthy` | 通过，status=`healthy` |
| 健康状态 `unhealthy` | 立即失败，`ErrUnhealthy`，status=`unhealthy`，并截取最后一条健康检查输出（上限 512 字节）供报告 |
| 健康状态 `starting`/未知 | 继续按间隔轮询 |
| inspect 瞬时错误（连接抖动、daemon 重启等非 NotFound） | 视作无结论，窗口内重试 |
| 窗口耗尽仍无结论 | 失败，`ErrHealthTimeout`，status=`starting` |
| 上层 ctx 取消 | 立即返回已累积的结果与原始 ctx 错误（绝不伪装成超时） |

**不运行门禁的场合**：更新前本就没在运行的容器（`include-stopped` 且不复活）重建后不会被启动，没有可观察对象——直接记 `updated`。

**通过后**：容器记 `updated`，随后按 `--snapshot-keep` 修剪快照。
**未通过后**：进入阶段 5。

## 阶段 5：回滚（rollback）

**触发条件**：门禁未通过，且 `--rollback-on-unhealthy=true`，且该容器本周期有快照。三者缺一，容器直接记 `failed`（若独缺快照，错误信息会注明"no pre-update snapshot available for rollback"），不健康的新容器保持现状交由运维处置。

**拒绝回滚的场合**：快照本身无效（报 `ErrSnapshotInvalid`）；快照属于 Drydock 自身容器（携带 `com.centurylinklabs.watchtower` 标签——v0.1 不支持自回滚）。

**回滚序列**（`pkg/rollback/restore.go`，步骤顺序是契约的一部分）：

1. **先取证**：截取失败容器最后 50 行日志（必须第一步——`AutoRemove` 容器一停就会自我销毁，这是唯一取证窗口）；
2. 把失败容器改名 `drydock-failed-<name>-<unixnano>`（释放原名、保留现场；v0.1 永不删除它）；
3. 优雅停止改名后的容器（SIGTERM → `--stop-timeout` 窗口 → SIGKILL；只停不删，NotFound 视作成功）；
4. 确认快照钉住的旧镜像仍在本机（`ImageInspect` 按**镜像 ID** 查验），缺失则中止并报 `ErrRollbackImageMissing`——此前的改名/停止不会回退；
5. 从快照的深拷贝推导 create/host/network 配置（原 `Config` 原样透传，不做上游的镜像默认值剔除，以保留"显式设置=镜像默认"的覆盖；**镜像按不可变 ID（`sha256:...`）创建而非 tag**——回滚发生时同名 tag（如 `app:latest`）已被更新流程重新 pull 指向新镜像，按 tag 创建会原样重启刚失败/被投毒的新镜像，按 ID 创建则保证"第 4 步查验的镜像"与"实际运行的镜像"逐字节一致；剥离旧容器 ID 短别名）；
6. 以**原名** `ContainerCreate`；
7. 非主机网络模式下，重演上游的网络重连舞步：先断开创建时附带的单端点，再逐一接回快照记录的全部网络；
8. `ContainerStart`——**只有这步成功才算回滚成功**。

**失败语义**：步骤 2/3 失败 → 中止且不创建任何新容器，失败容器原样保留（绝不被删除）；步骤 6/7/8 失败 → 尽力把改名的失败容器重新启动（避免双重停机）、强制删除半成品新容器（把原名让给下次尝试），并仍返回错误。

**结局**：回滚成功 → 容器记 `rolled-back`，`NewImageRef` 指回旧镜像，服务回到更新前状态；回滚失败 → 记 `failed`，错误信息同时含门禁失败与回滚失败两层原因。

## 周期报告

每轮更新结束后，`pkg/updatereport` 把安全环视角的周期汇总（`safeflow.CycleReport`）渲染为每容器一行的表——列为 `NAME / STATUS / IMAGE / PRECHECK / HEALTH / ROLLBACK / ERROR`，缺失子结构渲染为 `—`：

- **控制台**：始终输出；
- **推送**：配置了 `--notification-url`（shoutrrr，与上游通知同一旗标）时，经同一渠道推送；发送器构建失败降级为仅控制台，不拖垮更新器；
- **静默规则**：周期内没有任何 `updated` / `failed` / `rolled-back` 容器时不发推送（全部 `fresh`/`skipped` 的安静周期不扰民）。

## 故障速查

| 现象（报告列） | 根因 | 处置 |
|---|---|---|
| `skipped` + `blocked-major` / `blocked-prerelease` / `blocked-unknown-tag` / `blocked-no-healthcheck` | 预检策略命中 | 确认是否要放行：调整对应旗标或给容器打 `com.drydock.updater.precheck=false` |
| `failed` + "no pre-update snapshot available for rollback" | 门禁失败但快照缺失（阶段 2 曾失败或 `--snapshot=false`） | 手动处置新容器；检查 `--snapshot-dir` 可写性 |
| `failed` + `ErrHealthTimeout`（health 列为 `starting`） | 门禁窗口内健康检查一直未出结论 | 加大 `--health-timeout` 或检查镜像健康检查配置 |
| `failed` + `ErrUnhealthy`（health 列为 `unhealthy`，附 512 字节输出） | 新版本健康检查不过 | 看 `drydock-failed-*` 容器与日志尾部；问题修复前保持回滚态 |
| `rolled-back` | 更新被判不健康且已自动恢复 | 服务已回旧版；排查新镜像后等下个周期 |
| `failed` + `ErrRollbackImageMissing` | 旧镜像已被从主机删除（如外部清理） | 手动拉回旧镜像或从编排清单重建 |
| 大量 `drydock-failed-*` 容器堆积 | 回滚取证现场（有意保留） | 确认无用后手动 `docker rm` |
