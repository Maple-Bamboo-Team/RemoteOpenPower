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

Windows 服务模式要求配置路径为绝对路径：

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

服务日志同时写入控制台和日志目录，文件名为 `YYYY-MM-DD_HHmm_NNN.log`。交互运行默认使用配置文件旁的 `logs`；Linux systemd 部署必须设置 `REMOTE_OPEN_POWER_LOG_DIR=/var/log/remote-open-power`，该目录由服务账户持有。日志等级为 `INFO`、`WARN`、`ERROR`、`FATAL`，panic 会附带崩溃报告。

## 构建与测试

常规检查：

```text
cargo test --all-targets --locked
cargo clippy --all-targets --locked -- -D warnings
```

在 Windows 上串行构建 Windows 和 Linux 发行版：

```powershell
.\scripts\build-both.ps1
```

脚本使用 `cargo-zigbuild` 构建 Linux 目标，先执行 `cargo clean`，Cargo 缓存和临时文件放在 `E:\Catch\Cargo`，最终产物保留在本项目的 `target`。Zig 不在 PATH 时使用 `-ZigPath` 指定可执行文件；只使用本地依赖缓存时添加 `-Offline`。

## 安全边界

- 客户端只能提交服务端目录中的主机 ID，不能覆盖 MAC、IP、端口或执行系统命令。
- 客户端身份来自便携静态私钥；显示名称和 Windows 设备名不参与授权。
- 服务端撤销凭据后会热加载 ACL、关闭对应活动连接，并校验身份后删除仍在原位置的签发文件；已复制到客户端的文件无法远程擦除，但会立即失效。
- “在线”是网络探测结果，不是目标设备的密码学身份证明。
- 原生 WoL magic packet 在二层网络上没有认证，仍需 VLAN、交换机 ACL 和防火墙限制不可信设备。
- 服务端不会自行重发。只有客户端收到执行回执、等待 60 秒仍未上线后，才会凭一次性票据申请第二次发送。

详细协议、威胁模型和剩余风险见 [安全审计](docs/secure.md)。
