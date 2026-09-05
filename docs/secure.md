# RemoteOpenPower 安全复审

**范围：** `protocol.rs` / `security.rs` / `server.rs` / `client.rs` / `config.rs` / `tui.rs` / `main.rs` / `probe.rs` / `wol.rs`
**口径：** 只列高危与中危。低危硬化、质量问题、残余威胁模型说明不收录。
**总评：** 未发现未认证唤醒、Noise 认证绕过或 ACL 选错条目。高/中危集中在配置与协议不变量分裂、默认暴露面、目录侦察、共享 PSK 与跨客户端互斥。

## 2026-09-05 源码复核状态

| ID | 当前状态 | 依据 |
|----|----------|------|
| H1 | **已修复** | 配置层主机 ID 与客户端 ID 均复用协议边界；超长 host ID 和保留 client ID 有回归测试 |
| M1 | **仍保留（部署策略）** | 默认仍为 `0.0.0.0` + `::` 双栈全接口；必须配合防火墙或显式改为受信地址 |
| M2 | **已缓解，仍有分布式残余风险** | 未完成握手限制为每 IP 2 条，绝对握手超时 5 秒；多个源地址仍可耗尽全局握手槽 |
| M3 | **已修复** | 线上 `HostSummary` 只含不透明 `host_id`，测试验证序列化结果不含 MAC/IP |
| M4 | **未修复** | 每份 `CredentialBundle` 仍携带部署级 `shared_secret`；撤销单客户端不会撤销其 PSK 能力 |
| M5 | **已修复** | 冷却表按认证客户端公钥和 host ID 双维度隔离；跨客户端不互相阻塞，同客户端仍保持 10 秒冷却 |

本节是对下方原始发现的当前状态标注；下方问题描述保留用于审计追溯。

---

## 高危

### H1 配置层接受、协议层拒绝：超长 hostname 可使主机目录全面失败

**位置**

- [`config.rs`](../src/config.rs) `HostConfig::validate` / `is_valid_hostname`：主机名上限 128 字节
- [`config.rs`](../src/config.rs) `HostConfig::host_id`：`hostname.trim().to_ascii_lowercase()`
- [`protocol.rs`](../src/protocol.rs) `validate_id` / `MAX_ID_BYTES`：线上标识上限 **64** 字节
- [`server.rs`](../src/server.rs) `make_response` → `ServerEnvelope::validate()`

**问题**

`config.validate()` 允许保存合法 DNS 风格、长度 65–128 的主机名。该名经 `host_id()` 进入 `HostSummary.host_id` 后，`ListHosts` 在组装响应时被 `validate_id` 拒绝。`process_envelope` 把这次失败当成请求错误并 **拆掉连接**。

任意一条超长主机即可让 **所有** 已认证客户端拿不到目录，也无法唤醒。配置校验与线上校验不是同一套函数。

同类分裂：`config::validate_client_id` 比 `protocol::validate_id` 更松（不要求首尾字母数字，不拒绝 `.` / `..`）。能写入配置，在握手阶段再失败。

**影响**

可用性：合法配置导致控制面拒绝服务。操作者按文档添加主机后，整个守护进程对客户端不可用。

**修复**

1. 配置层与线上共用 `protocol::validate_id`。
2. `host_id` 独立字段，强制 ≤ 64；`hostname` 仅作显示名。
3. 启动时若存量配置违反线上不变量，fail-closed，不要部分上线。
4. 回归测试：65 字节 hostname 的配置必须在 `AppConfig::validate` / `ServerRuntime::new_with_components` 被拒。

---

## 中危

### M1 默认监听全接口，威胁模型写的是 LAN

**位置**

- [`config.rs`](../src/config.rs) `default_bind_address()` → `"::"`
- [`config.rs`](../src/config.rs) `default_bind_address_v4()` → `"0.0.0.0"`
- [`config.rs`](../src/config.rs) `dual_stack` 默认 `true`
- [`tui.rs`](../src/tui.rs) 部署模板未限制绑定地址

**问题**

出厂配置把 TCP 控制面绑在所有接口。Noise + ACL 可以挡住假唤醒，但默认暴露意味着：

- 控制面可从非 LAN 路径到达（路由/NAT/防火墙允许时）
- 凭据失窃后攻击者不必身处目标二层
- 与 M2 叠加后，互联网侧可打握手槽

systemd 片段限制了地址族，没有限制绑定地址。

**影响**

攻击面从“LAN 守护进程”扩大为“任何能打到该 TCP 端口的主机”。密码学仍是必要条件，但默认部署与文档中的 LAN 假设不一致。

**修复**

默认绑私网或未指定地址改为必须显式配置。`::` / `0.0.0.0` 只能是操作者明确选择。部署文档要求防火墙只放行管理网。

---

### M2 未认证握手槽耗尽（慢握手）

**位置**

- [`server.rs`](../src/server.rs) `MAX_CONCURRENT_HANDSHAKES = 16`
- [`server.rs`](../src/server.rs) `MAX_CONNECTIONS_PER_IP = 8`
- [`security.rs`](../src/security.rs) `HANDSHAKE_TIMEOUT = 5s`
- [`server.rs`](../src/server.rs) `handle_connection`：`server_handshake` 返回前一直持有 `handshake_permit`

**问题**

对手 **不需要 PSK**。连上后按字节滴送，即可占用一个握手槽直到 5 秒超时。每 IP 8 条连接，**两个源 IP** 即可占满全局 16 个握手槽。已认证会话不受影响，但新的合法客户端无法完成握手。

存在每 IP 每分钟 12 次的握手速率限制，挡不住少量 IP 上的并发慢握手。

**影响**

预认证拒绝服务。与 M1（全接口监听）同时存在时，可从网外打满握手池。

**修复**

1. 未完成握手单独按 IP 限额（应明显小于 8，或从全局 16 中独立计）。
2. 缩短首字节/首帧超时，保留总超时。
3. 槽满时优先拒绝未完成握手，不要误伤已认证连接。
4. 回归：16 个慢连接期间，第 17 个合法握手必须仍有明确失败原因，且耗尽源不能长期占槽。

---

### M3 主机目录把 MAC/IP 交给客户端（与模块合同相反）

**位置**

- [`server.rs`](../src/server.rs) 模块文档：MAC / IP / OS 命令不得过信任边界
- [`client.rs`](../src/client.rs) 模块文档：线上消息不含 MAC / IP
- [`protocol.rs`](../src/protocol.rs) `HostSummary { host_id, hostname, ip, mac }`
- [`server.rs`](../src/server.rs) `ListHosts` 发送完整 `summaries`

**问题**

唤醒参数确实只能是 opaque host id，这条合同成立。但 `ListHosts` 把每台授权主机的 **主机名、IP、MAC** 明文交给客户端。TUI / CLI 会展示这些字段。

失窃的客户端凭据 = 完整 LAN 资产表。拿到 MAC 后，同一二层上的攻击者可以 **绕过守护进程** 直接发送魔法包（L2 WoL 无认证）。

**影响**

机密性 / 侦察。远程凭据失窃从“能唤醒已授权主机”升级为“掌握网卡地址并可在 LAN 上绕过控制面”。与文档声称的边界直接矛盾。

**修复**

线上目录只返回 `host_id` 与状态；MAC/IP 留在服务端。若操作者界面必须显示，应标为敏感、仅本地配置视图使用，不进 `ServerEvent::Hosts`。

---

### M4 全局共享 PSK：撤销客户端不能切断握手能力

**位置**

- [`client.rs`](../src/client.rs) `CredentialBundle.shared_secret`
- [`tui.rs`](../src/tui.rs) `issue_credential` 把服务端 PSK 写入每份 bundle
- [`security.rs`](../src/security.rs) `Noise_IKpsk0+psk2`，PSK 参与第一趟与完成转录

**问题**

每份客户端凭据同时包含：

1. 该客户端静态私钥（可冒充该客户端）
2. **整个部署** 的 Noise PSK

从 ACL 删除该客户端可以挡住冒充，但持有旧 bundle 的人仍能完成 IK 第一趟：解密 ClientHello、消耗握手槽、探测时钟窗。代码中没有 PSK 轮换与全体再签发流程。

**影响**

撤销不完整。一份丢失的笔记本凭据长期保留部署级握手密钥。与 M2 叠加后，被撤销客户端仍是预认证 DoS 的合格参与者。

**修复**

长期：PSK 只留在服务端；客户端靠各自静态钥 + 钉住的服务端钥。
短期：文档规定“撤销 = ACL 删除 **加** PSK 轮换并作废全部旧 bundle”；签发路径停止把 PSK 写入可拷贝文件，或使用每客户端派生 PSK。

---

### M5 全局 `WAKE_COOLDOWN` 允许已授权客户端互抢

**位置**

- [`server.rs`](../src/server.rs) `WAKE_COOLDOWN = 10s`
- [`server.rs`](../src/server.rs) `reserve_wake_targets`：`last_wake` 按 host id 记时间，**不分客户端**

**问题**

客户端 A 对 host X 的一次唤醒会让客户端 B 在 10 秒内得到 `RateLimited`。有权唤醒该主机的主体可以按冷却周期占坑，使其他已登记客户端无法唤醒。

对“全家同一信任域”可能可接受；对多客户端、多角色（学校、实验室、多操作员）是已认证拒绝服务。

**影响**

授权模型是“每客户端一份主机 ACL”，冷却却是全局互斥。恶意或失控的已登记客户端可以压制他人的唤醒。

**修复**

冷却键改为 `(host_id, client_key)`，或对同一 principal 限速、对全局只保留更高的包速率帽。跨客户端不应因一次成功/失败的 `wake()` 互相饿死。

---

## 对照

| ID | 严重度 | 类别 | 需要认证 | 默认配置即可触发 |
|----|--------|------|----------|------------------|
| H1 | 高 | 不变量 / 可用性 | 否（配置阶段） | 是（长主机名） |
| M1 | 中 | 暴露面 | 否 | 是 |
| M2 | 中 | 预认证 DoS | 否 | 是（尤其叠加 M1） |
| M3 | 中 | 侦察 / 文档合同 | 是（凭据） | 是 |
| M4 | 中 | 撤销 / 密钥管理 | 曾持有凭据 | 是 |
| M5 | 中 | 已认证 DoS | 是 | 是 |

---

## 建议修复顺序

1. **H1** 配置与协议共用 `validate_id`，启动 fail-closed
2. **M1** 默认绑定改私网
3. **M2** 未完成握手按 IP 限额并缩短首帧超时
4. **M3** 目录去掉 MAC/IP
5. **M4** PSK 轮换 / 从客户端 bundle 剥离共享秘密
6. **M5** 冷却改为 per-client 或拆分全局帽

修复时应补测试：超长 host_id、握手槽耗尽、目录不含 L2 地址、ACL 删除后旧 PSK 不能再完成传输。
