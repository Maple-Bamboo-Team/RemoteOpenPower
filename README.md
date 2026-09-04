# RemoteOpenPower

RemoteOpenPower 是一个纯 CLI 的 TCP Wake-on-LAN 工具。后端可运行在 Windows 或 Linux
局域网主机上。客户端授权根是随机静态公钥及其服务端 ACL；Windows 设备名只作为可选备注，
不参与密码学授权。程序不包含 GUI，也不会调用 shell 执行
远程命令。

## 构建

Cargo 下载缓存和临时文件放在 `E:\Catch\Cargo`，最终产物保留在仓库的 `target` 目录。
PowerShell 构建示例：

```powershell
$env:CARGO_HOME = 'E:\Catch\Cargo\Catch'
$env:RUSTUP_HOME = 'E:\Catch\Cargo\.rustup'
$env:TEMP = 'E:\Catch\Cargo\Catch\tmp'
$env:TMP = 'E:\Catch\Cargo\Catch\tmp'
cargo build --release
```

要同时生成 Windows 和 Linux 发行版，在 PowerShell 中执行：

```powershell
.\scripts\build-both.ps1
```

该脚本先运行 `cargo clean`，随后严格串行构建 Windows 原生发行版和 Linux
`cargo-zigbuild` 发行版，避免多个 Cargo 进程争用构建目录锁。下载缓存和临时文件仍全部位于
`E:\Catch\Cargo`，最终产物位于仓库的 `target`。只使用本地缓存时加 `-Offline`；如果 Zig
不在 PATH，可用 `-ZigPath 'G:\Program Files\zig-...\zig.exe'` 指定。

## 服务日志

服务模式会同时向控制台和日志文件写入 `INFO`、`WARN`、`ERROR`、`FATAL` 事件。前台 TUI
中的“实时事件”窗格就是控制台输出；直接使用 `--server` 时输出到标准输出。默认日志目录是
配置文件旁的 `logs`，文件名格式为 `YYYY-MM-DD_HHmm_NNN.log`。可通过
`REMOTE_OPEN_POWER_LOG_DIR` 指定其他目录；systemd 模板会使用
`/var/log/remote-open-power`。panic 报告包含线程、源码位置、payload 与完整 backtrace。

## 首次配置

直接运行程序，选择服务模式。服务菜单提供：

1. 列出全部开机项
2. 添加开机项
3. 修改或删除开机项
4. 监听与安全设置、签发客户端凭据
5. 保存并立即启动服务
q. 保存并退出（显示部署信息）

每个菜单操作完成后，按任意键会清屏并重新显示同一个服务菜单。添加、修改和安全设置
会自动写入 TOML 配置。选项 5 只保存并启动，不显示部署模板；选项 q 保存并退出时才显示
当前编译平台的部署信息。

客户端凭据签发时可填写一个设备备注，并选择它有权访问的主机。服务端默认生成按公钥命名的
`<公钥指纹>.credential.toml`（也支持固定的 `remote-open-power.credential.toml`）。将这个私有文件复制到任意客户端的普通配置文件旁边后，
客户端模式只询问服务端 IP/地址和端口；客户端 ID 由静态公钥的完整 SHA-256 指纹派生，
因此设备改名或换机不会使合法凭据失效。备注只会作为可选显示信息，
客户端不会读取或比较当前设备名，也不会把备注当作密钥。

长期便携凭据不能仅凭一个未经认证的 IP 安全下载，否则首次连接的中间人可以替换服务端
身份。这里采用服务端预签发凭据，并在每次连接时通过 Noise IKpsk0+psk2 动态协商新的会话密钥；
不会使用静默 TOFU，也不会在参数、日志或界面中显示 PSK/私钥。

## 参数启动

```text
remote-open-power --server --config /etc/remote-open-power/remote-open-power.toml
remote-open-power --client --config remote-open-power.toml --address 192.168.1.10 --port 45890
remote-open-power --client --config remote-open-power.toml --address 192.168.1.10 --port 45890 --wake pc-a,pc-b
```

服务端配置必须先由交互菜单生成。`--server` 只读现有配置，缺少文件、密钥、设备 ACL 或
角色混用时会拒绝启动。Linux 构建的选项 q 会输出直接启动命令和完整的 systemd unit，其中
包含专用低权限账户、能力清空、只读文件系统、私有临时目录和地址族限制；Windows 构建只
输出 Windows 前台 daemon 指令和 Windows 服务包装器注意事项，不生成 Linux unit。

启动后 stdout 会实时输出：监听地址、连接接收、设备身份确认、请求类型、WoL 下发结果、
在线探测和连接关闭。拒绝类日志有速率限制，避免连接洪泛填满 journald。

## 唤醒与重试

服务端只执行客户端明确提交的唤醒请求。WoL 发包调用完成后，服务端返回“已执行”回执；
该回执表示服务端已经提交唤醒包，不表示目标机器已经上线。客户端收到回执后在本地开始
60 秒倒计时。目标仍未上线时，客户端使用同一个操作 ID、目标集和 boot nonce，携带服务端
签发的一次性票据，明确申请且仅申请一次重发；收到第二次执行回执后，再由客户端本地等待
60 秒。第二个窗口结束后不再自动重发。

服务端不会根据计时器、进程恢复或启动状态自行补发 WoL。进程内账本只用于阻止同一请求
并发或重复执行；服务重启会丢弃这份临时状态，也不会因此产生新的发包动作。

## 安全边界

- 控制通道使用固定 Noise IKpsk0+psk2 套件、服务端公钥 pin、客户端静态公钥 ACL、PSK、严格
  方向序列号、短时钟窗口和两阶段握手重放缓存。
- 客户端 ID 是静态公钥的完整 SHA-256 十六进制指纹；服务端按公钥定位 ACL。设备备注和旧版
  设备名只用于迁移/显示，不能改变权限。
- 客户端只能提交服务端目录返回的不透明主机 ID。MAC、IP、端口和命令均不能从网络请求
  覆盖；WoL 使用 Rust 库直接发送固定 magic packet。
- 每 IP、每客户端和全局连接数有独立上限；帧、列表、请求、探测、监视器、速率和幂等
  账本均有硬上限。第二次唤醒必须携带绑定设备、操作、目标集和 boot nonce 的一次性票据。
- 在线状态是受服务端约束的观测结果，不是目标机器的密码学证明。需要强证明时，目标机器
  还需部署独立的双向认证 agent。
- 原生 WoL magic packet 在二层网络中没有认证。同 VLAN 的攻击者仍可自行发送唤醒包；应
  配合 VLAN、交换机 ACL 和主机防火墙限制广播范围。
- 业务幂等账本当前保存在内存中，只负责当前进程内的去重。服务端没有崩溃恢复补发逻辑；
  是否发起唯一一次重试始终由客户端在收到执行回执并等待 60 秒后决定。
- Windows 当前提供前台 daemon，不内置 SCM dispatcher/安装器。若通过受信服务包装器部署，
  必须使用受限 service SID，把配置放入受保护的固定目录，并显式授予该 SID 只读权限；不要
  直接用 `sc create` 注册这个控制台入口，也不要从普通用户可写目录以 LocalSystem/管理员运行。
- 程序创建的私密 TOML 会在 Windows 上原子附带受保护 DACL；手工复制 credential 后必须保证
  目标文件和全部父目录仍只有目标用户、SYSTEM 与管理员可访问。Linux 配置要求正确 owner、
  `0600`、单硬链接且不经过符号链接。
