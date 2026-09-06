# RemoteOpenPower

跨平台的终端 Wake-on-LAN 工具。服务端部署在目标机器所在局域网，客户端通过加密连接请求唤醒已授权主机。

项目提供：

- Windows / Linux 服务端与客户端
- TUI 配置、凭据签发、主机选择和运行日志
- Noise IKpsk0+psk2 加密通道、服务端公钥固定和客户端公钥 ACL
- IPv4 广播，以及 IPv6 单播/链路本地组播 WoL
- 客户端控制的两次唤醒流程：执行后等待 60 秒，超时才申请一次重发

## 快速开始

构建并启动 TUI：

```powershell
cargo build --release
.\target\release\RemoteOpenPower.exe
```

Linux：

```bash
cargo build --release
./target/release/RemoteOpenPower
```

首次使用选择“服务模式”，依次完成：

1. 添加开机项。
2. 设置监听地址和端口。
3. 签发客户端凭据并选择其可访问的主机。
4. 进入“部署”保存配置并查看当前平台的启动方式。

将生成的 `*.credential.toml` 私下复制到客户端目录。客户端目录中只能保留一份凭据文件。启动程序、选择“终端模式”，填写服务端地址和端口即可连接；凭据不绑定 Windows 设备名，可以随软件一起迁移。

不要提交、发送到群聊或放入命令行：

- `remote-open-power.toml` 服务端配置
- `*.credential.toml` 客户端凭据
- PSK、静态私钥和重试票据

这些文件已由 `.gitignore` 排除。

## 命令行

直接运行已配置的服务端：

```bash
sudo -u remote-open-power env REMOTE_OPEN_POWER_LOG_DIR=/var/log/remote-open-power \
  /usr/local/bin/remote-open-power --server --config /etc/remote-open-power/remote-open-power.toml
```

Windows 服务模式接受相对路径（相对启动时的工作目录），部署页会输出绝对路径：

```powershell
$config = (Resolve-Path .\remote-open-power.toml).Path
.\RemoteOpenPower.exe --server --config $config
```

非交互客户端：

```text
remote-open-power --client --config remote-open-power.toml --address 192.168.1.10 --port 45890
remote-open-power --client --config remote-open-power.toml --address 192.168.1.10 --port 45890 --wake pc-a,pc-b
```

不带 `--wake` 时列出可用主机及状态。完整参数见：

```text
remote-open-power --help
```

## 部署与日志

TUI 的“部署”页按当前平台输出启动方式。Linux 会生成 systemd unit 模板；Windows 当前以前台 daemon 运行，不应把控制台程序直接注册为 SCM 服务。

Linux 服务配置采用 `root:remote-open-power 0640`，配置目录采用 `root:remote-open-power 0750`，日志目录由服务账户持有并采用 `0750`。程序会拒绝其他用户可读、组可写、世界可访问、硬链接或符号链接的私密文件；通过 TUI 重新保存已部署配置时会保留安全的服务属组读取权限。

Windows 私密文件只允许当前用户、文件所有者、SYSTEM 和 Administrators 访问，并拒绝不可信所有者、重解析点和硬链接。复制凭据后若权限检查失败，先限制文件 ACL，不要关闭检查。普通只读句柄可并存；写入通过私密临时文件刷盘后原子替换。

主机和凭据修改在保存后热加载；修改主机目标会关闭旧会话并更新目录版本。监听地址或端口变化会停止旧监听，需重新启动服务（systemd 可按失败重启策略启动新配置）。停止完成意味着监听和连接工作线程均已退出。

服务日志同时写入控制台和日志目录，文件名为 `YYYY-MM-DD_HHmm_NNN.log`。交互运行默认使用配置文件旁的 `logs`；Linux systemd 部署必须设置 `REMOTE_OPEN_POWER_LOG_DIR=/var/log/remote-open-power`，该目录由服务账户持有。日志等级为 `INFO`、`WARN`、`ERROR`、`FATAL`，panic 会附带崩溃报告。

## WoL 网络出口

FRP 只转发客户端与服务端的控制连接；WoL UDP 包由局域网内的服务端重新发送，不使用 FRP 地址作为源地址。

IPv4 发包时枚举当前有效网卡，按目标 IP 所在网段选择最长前缀匹配，使用该网卡的实际子网掩码计算定向广播，并绑定源 IP 和出口接口。例如源地址 `192.168.0.5/24` 对应广播 `192.168.0.255`，不再使用 `0.0.0.0` 加 `255.255.255.255` 让默认路由选择出口。

目标必须位于服务端直接连接、支持广播的子网。没有匹配网卡、多个接口同等匹配、目标是网络/广播地址或使用 `/31`、`/32` 时会明确失败，不回退到全局广播。成功提交 UDP 后，服务日志记录目标 IP、接口索引、实际源地址和广播目的地址；这不代表硬件已经唤醒。IPv6 的单播/组播行为不变。

Linux 网卡枚举需要 `AF_NETLINK`，新版部署模板已包含它，仍保持 `CapabilityBoundingSet=` 为空。已有 systemd unit 请将对应行更新为 `RestrictAddressFamilies=AF_INET AF_INET6 AF_NETLINK`，再执行 `sudo systemctl daemon-reload` 和 `sudo systemctl restart remote-open-power`；无需授予 `CAP_NET_RAW` 或 `CAP_NET_ADMIN`。

## 构建与测试

常规检查：

Windows 手动运行检查前，先设置缓存和产物目录：

```powershell
$env:CARGO_HOME = 'E:\Catch\Cargo\Catch'
$env:RUSTUP_HOME = 'E:\Catch\Cargo\.rustup'
$env:TEMP = 'E:\Catch\Cargo\Catch\tmp'
$env:TMP = $env:TEMP
$env:CARGO_TARGET_DIR = Join-Path $PWD 'target'
```

```text
cargo fmt --all --check
rustfmt --edition 2024 --check src/server_tests.rs src/tui_tests.rs src/tui_core.rs
cargo test --all-targets --locked
cargo clippy --all-targets --locked -- -D warnings
```

在 Windows 上串行构建 Windows 和 Linux 发行版：

```powershell
.\scripts\build-both.ps1
```

脚本使用 `cargo-zigbuild` 构建 Linux 目标，先执行 `cargo clean`，Cargo 缓存和临时文件放在 `E:\Catch\Cargo`，最终产物保留在本项目的 `target`。`.cargo/config.toml` 将编译中间文件放在 Cargo 缓存下按工作区隔离的 `build` 目录（本机已验证 Cargo 1.97.1）；Linux 原生使用自己的 Cargo 缓存路径。Zig 不在 PATH 时使用 `-ZigPath` 指定可执行文件；只使用本地依赖缓存时添加 `-Offline`。

未指定 `-ZigPath` 时，脚本优先选择 G 盘 `Program Files` 中版本最高的 Zig 正式版，再查 PATH。当前已安装 0.16.0。按项目维护者要求，仅 `ignoring deprecated linker optimization setting '1'` 警告不阻塞验收；日志仍显示该警告，不屏蔽其他链接器诊断。

本项目不使用 WSL。Windows 上的 Linux 交叉编译只能证明目标可构建，不能替代 Linux 原生权限、systemd 或实际网卡唤醒测试。

`cargo test --all-targets --locked` 包括安全不变量、回环 Noise 会话、TUI 和独立进程 CLI 回归，测试唤醒器不会发送真实 WoL。审计项目和专项测试对应关系见 [安全审计](docs/secure.md#回归测试)。

## 安全边界

- 客户端只能提交服务端目录中的主机 ID，不能覆盖 MAC、IP、端口或执行系统命令。
- 客户端身份来自便携静态私钥；显示名称和 Windows 设备名不参与授权。
- 服务端撤销凭据后会热加载 ACL、关闭对应活动连接，并校验身份后删除仍在原位置的签发文件；已复制到客户端的文件无法远程擦除，但会立即失效。
- “在线”是网络探测结果，不是目标设备的密码学身份证明。
- 原生 WoL magic packet 在二层网络上没有认证，仍需 VLAN、交换机 ACL 和防火墙限制不可信设备。
- 服务端不会自行重发。只有客户端收到执行回执、等待 60 秒仍未上线后，才会凭一次性票据申请第二次发送。
- 在服务端操作记录有效时，重连恢复只重发回执并恢复在线监控，不重发 WoL；同一次尝试的本地倒计时不会被恢复回执重置。客户端在本次尝试开始 13 分钟后停止自动恢复，早于服务端 15 分钟操作记录过期，并为重试预留 90 秒。服务重启会丢失内存记录，不提供跨服务重启的恢复保证。
- 只有请求中的全部目标上线才显示 `OK`。部分拒绝、全部拒绝和等待超时均不是成功；非交互客户端返回非零退出码。

详细协议、威胁模型和剩余风险见 [安全审计](docs/secure.md)。
