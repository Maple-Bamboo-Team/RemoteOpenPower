mod client;
mod config;
mod logging;
mod probe;
mod protocol;
mod security;
mod server;
mod tui;
mod wol;

use clap::Parser;
use std::{
    collections::{HashMap, HashSet},
    io::{self, IsTerminal, Write},
    path::PathBuf,
    thread,
    time::{Duration, Instant},
};

const RESET: &str = "\x1b[0m";
const BOLD: &str = "\x1b[1m";
const CYAN: &str = "\x1b[36m";
const GREEN: &str = "\x1b[32m";
const YELLOW: &str = "\x1b[33m";
const RED: &str = "\x1b[31m";
const DIM: &str = "\x1b[2m";
const SPINNER: [char; 4] = ['|', '/', '-', '\\'];
const WAKE_WINDOW: Duration = Duration::from_secs(60);

#[cfg(windows)]
#[link(name = "msvcrt")]
unsafe extern "C" {
    fn _getch() -> i32;
}

#[derive(Debug, Parser)]
#[command(
    name = "remote-open-power",
    version,
    about = "Secure LAN Wake-on-LAN terminal"
)]
struct Cli {
    /// Run the TCP WoL daemon.
    #[arg(long)]
    server: bool,
    /// Run the non-interactive client command.
    #[arg(long)]
    client: bool,
    /// TOML settings path. Client credentials load from an adjacent private bundle.
    #[arg(long, default_value = config::DEFAULT_CONFIG_FILE)]
    config: PathBuf,
    /// Server bind IP literal override (server mode).
    #[arg(long)]
    bind: Option<String>,
    /// TCP port override.
    #[arg(long)]
    port: Option<u16>,
    /// Server address override (client mode).
    #[arg(long)]
    address: Option<String>,
    /// Host IDs to wake, comma separated. Omit to list hosts/statuses.
    #[arg(long, value_delimiter = ',')]
    wake: Vec<String>,
}

fn main() {
    logging::install_panic_hook();
    if let Err(error) = run() {
        eprintln!("{RED}error:{RESET} {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let cli = Cli::parse();
    if cli.server && cli.client {
        return Err("--server and --client are mutually exclusive".to_owned());
    }
    if cli.server {
        return server::run_server(&cli.config, cli.bind, cli.port).map_err(|e| e.to_string());
    }
    if cli.client {
        return run_client_cli(&cli);
    }
    tui::run(&cli.config)
}

// The retired line-oriented menu is kept out of the build while the current
// TUI and non-interactive commands share the production runtime below.
#[cfg(any())]
mod retired_text_menu {
    use super::*;

    fn interactive_mode(config_path: &Path) -> Result<(), String> {
        print_banner();
        loop {
            println!("\n{BOLD}{CYAN}选择运行模式{RESET}");
            println!("  {CYAN}1{RESET}  服务模式");
            println!("  {CYAN}2{RESET}  终端模式");
            println!("  {CYAN}q{RESET}  退出");
            match prompt(">>", "")?.to_ascii_lowercase().as_str() {
                "1" => return configure_server(config_path),
                "2" => return configure_client(config_path),
                "q" | "quit" | "exit" => return Ok(()),
                _ => println!("{YELLOW}请输入 1、2 或 q。{RESET}"),
            }
        }
    }

    fn configure_server(config_path: &Path) -> Result<(), String> {
        // The interactive setup is also the first-run bootstrap path.  Parse the
        // file with all structural/permission checks, then create server-only
        // credentials locally before the first save; `save`/`run_server` still
        // perform the complete fail-closed validation.
        let mut config =
            config::AppConfig::load_unvalidated(config_path).map_err(|e| e.to_string())?;
        config.ensure_secret();
        config
            .ensure_server_identity_material()
            .map_err(|e| e.to_string())?;
        // A server deployment must not retain a client private key.
        config.client = config::ClientConfig::default();

        loop {
            print_server_dashboard(&config, config_path);
            println!("\n{BOLD}操作{RESET}");
            println!("  {CYAN}1{RESET}  列出全部开机项");
            println!("  {CYAN}2{RESET}  添加开机项");
            println!("  {CYAN}3{RESET}  修改或删除开机项");
            println!("  {CYAN}4{RESET}  监听与安全设置");
            println!("  {CYAN}5{RESET}  保存并立即启动服务");
            println!("  {CYAN}q{RESET}  保存并退出（显示部署信息）");
            match prompt("server", "1")?.to_ascii_lowercase().as_str() {
                "1" => {
                    list_server_hosts(&config);
                    pause_and_clear()?;
                }
                "2" => {
                    if add_server_host(&mut config) {
                        save_server_config(&mut config, config_path)?;
                    }
                    pause_and_clear()?;
                }
                "3" => {
                    if edit_server_host(&mut config) {
                        save_server_config(&mut config, config_path)?;
                    }
                    pause_and_clear()?;
                }
                "4" => {
                    configure_server_security(&mut config, config_path)?;
                    save_server_config(&mut config, config_path)?;
                    pause_and_clear()?;
                }
                "5" => {
                    save_server_config(&mut config, config_path)?;
                    if prompt_yes_no("立即启动服务端", true)? {
                        let runtime_path = std::fs::canonicalize(config_path)
                            .map_err(|error| format!("无法解析服务配置路径: {error}"))?;
                        return server::run_server(&runtime_path, None, None)
                            .map_err(|e| e.to_string());
                    }
                    pause_and_clear()?;
                }
                "q" | "quit" | "exit" => {
                    if prompt_yes_no("保存当前配置", true)? {
                        save_server_config(&mut config, config_path)?;
                        print_server_deployment(&config, config_path)?;
                        pause_before_exit()?;
                    }
                    return Ok(());
                }
                _ => {
                    println!("{YELLOW}请输入 1、2、3、4、5 或 q。{RESET}");
                    pause_and_clear()?;
                }
            }
        }
    }

    fn pause_and_clear() -> Result<(), String> {
        println!("\n{DIM}按任意键继续...{RESET}");
        io::stdout().flush().map_err(|error| error.to_string())?;
        wait_for_key().map_err(|error| error.to_string())?;
        clear_screen();
        Ok(())
    }

    fn pause_before_exit() -> Result<(), String> {
        println!("\n{DIM}按任意键退出...{RESET}");
        io::stdout().flush().map_err(|error| error.to_string())?;
        wait_for_key().map_err(|error| error.to_string())
    }

    fn wait_for_key() -> io::Result<()> {
        // A redirected stdin must remain line-oriented so scripted deployments and
        // tests can provide a newline.  Interactive Windows consoles can consume
        // one key without requiring Enter through the CRT's native `_getch`.
        if !io::stdin().is_terminal() {
            let mut ignored = String::new();
            io::stdin().read_line(&mut ignored)?;
            return Ok(());
        }

        #[cfg(windows)]
        {
            unsafe {
                let _ = _getch();
            }
            println!();
            Ok(())
        }

        #[cfg(not(windows))]
        {
            // POSIX terminals are normally line-buffered without a terminal-
            // control dependency; Enter is the portable fallback there.
            let mut ignored = String::new();
            io::stdin().read_line(&mut ignored)?;
            Ok(())
        }
    }

    fn clear_screen() {
        // ANSI clear is supported by modern Windows Terminal, PowerShell, and
        // Unix terminals, and avoids spawning a shell just to redraw the menu.
        print!("\x1b[2J\x1b[H");
        let _ = io::stdout().flush();
    }

    fn print_server_dashboard(config: &config::AppConfig, config_path: &Path) {
        println!("\n{BOLD}{CYAN}RemoteOpenPower{RESET} {DIM}server configuration{RESET}");
        println!("  config   {}", config_path.display());
        println!(
            "  listen   {}:{}  {}",
            config.server.bind_address,
            config.server.port,
            if config.server.dual_stack {
                "dual-stack"
            } else {
                "single-stack"
            }
        );
        println!(
            "  entries  {}    clients {}    headers {}",
            config.hosts.len(),
            config.security.allowed_clients.len(),
            config.security.custom_headers.len()
        );
        println!("{}", "─".repeat(72));
    }

    fn list_server_hosts(config: &config::AppConfig) {
        println!("\n{BOLD}{CYAN}开机项{RESET}");
        if config.hosts.is_empty() {
            println!("  {DIM}(暂无条目){RESET}");
            return;
        }
        println!(
            "  {:>3}  {:<24} {:<17} {:<40}",
            "#", "HOSTNAME", "MAC", "IP"
        );
        for (index, host) in config.hosts.iter().enumerate() {
            println!(
                "  {:>3}  {:<24} {:<17} {:<40}",
                index + 1,
                host.hostname,
                host.mac,
                host.ip
            );
        }
    }

    fn add_server_host(config: &mut config::AppConfig) -> bool {
        println!("\n{BOLD}{CYAN}添加开机项{RESET}");
        let hostname = match prompt("主机名", "") {
            Ok(value) if !value.is_empty() => value,
            Ok(_) => {
                println!("{YELLOW}已取消。{RESET}");
                return false;
            }
            Err(error) => {
                println!("{RED}{error}{RESET}");
                return false;
            }
        };
        let mac = match prompt("MAC 地址", "") {
            Ok(value) => value,
            Err(error) => {
                println!("{RED}{error}{RESET}");
                return false;
            }
        };
        let ip = match prompt("IP 地址", "") {
            Ok(value) => value,
            Err(error) => {
                println!("{RED}{error}{RESET}");
                return false;
            }
        };
        let host = config::HostConfig {
            hostname,
            display_name: String::new(),
            mac,
            ip,
            wol_port: 9,
            probe_timeout_ms: 1_000,
            probe_port: 0,
            wol_ipv6_interface: 0,
        };
        match host.validate(config.security.allow_public_targets) {
            Ok(())
                if !config
                    .hosts
                    .iter()
                    .any(|item| item.host_id() == host.host_id()) =>
            {
                config.hosts.push(host);
                println!("{GREEN}开机项已加入配置。{RESET}");
                true
            }
            Ok(()) => {
                println!("{RED}重复主机 ID，未添加。{RESET}");
                false
            }
            Err(error) => {
                println!("{RED}主机无效: {error}{RESET}");
                false
            }
        }
    }

    fn edit_server_host(config: &mut config::AppConfig) -> bool {
        if config.hosts.is_empty() {
            println!("{YELLOW}暂无可修改的开机项。{RESET}");
            return false;
        }
        list_server_hosts(config);
        let index = match prompt("条目编号", "") {
            Ok(value) => match value.parse::<usize>() {
                Ok(index) if (1..=config.hosts.len()).contains(&index) => index - 1,
                _ => {
                    println!("{RED}编号无效。{RESET}");
                    return false;
                }
            },
            Err(error) => {
                println!("{RED}{error}{RESET}");
                return false;
            }
        };
        println!("  {CYAN}1{RESET} 修改   {CYAN}2{RESET} 删除   {CYAN}q{RESET} 取消");
        let action = match prompt("action", "1") {
            Ok(value) => value.to_ascii_lowercase(),
            Err(error) => {
                println!("{RED}{error}{RESET}");
                return false;
            }
        };
        if action == "2" {
            let removed = config.hosts.remove(index);
            println!("{GREEN}已删除 {}。{RESET}", removed.hostname);
            return true;
        }
        if action != "1" {
            return false;
        }
        let old = config.hosts[index].clone();
        let hostname = match prompt("主机名", &old.hostname) {
            Ok(value) => value,
            Err(error) => {
                println!("{RED}{error}{RESET}");
                return false;
            }
        };
        let mac = match prompt("MAC 地址", &old.mac) {
            Ok(value) => value,
            Err(error) => {
                println!("{RED}{error}{RESET}");
                return false;
            }
        };
        let ip = match prompt("IP 地址", &old.ip) {
            Ok(value) => value,
            Err(error) => {
                println!("{RED}{error}{RESET}");
                return false;
            }
        };
        let updated = config::HostConfig {
            hostname,
            display_name: old.display_name.clone(),
            mac,
            ip,
            wol_port: old.wol_port,
            probe_timeout_ms: old.probe_timeout_ms,
            probe_port: old.probe_port,
            wol_ipv6_interface: old.wol_ipv6_interface,
        };
        let duplicate = config
            .hosts
            .iter()
            .enumerate()
            .any(|(other, host)| other != index && host.host_id() == updated.host_id());
        match updated.validate(config.security.allow_public_targets) {
            Ok(()) if !duplicate => {
                config.hosts[index] = updated;
                println!("{GREEN}开机项已更新。{RESET}");
                true
            }
            Ok(()) => {
                println!("{RED}主机 ID 与其他条目重复。{RESET}");
                false
            }
            Err(error) => {
                println!("{RED}主机无效: {error}{RESET}");
                false
            }
        }
    }

    fn configure_server_security(
        config: &mut config::AppConfig,
        config_path: &Path,
    ) -> Result<(), String> {
        println!("\n{BOLD}{CYAN}监听与安全设置{RESET}");
        config.server.bind_address = prompt("监听地址 (IP literal)", &config.server.bind_address)?;
        config.server.port = prompt_u16("监听端口", config.server.port)?;
        config.server.dual_stack = prompt_yes_no("启用双栈", config.server.dual_stack)?;
        println!("\n  {DIM}自定义请求头：name=value；空行结束。{RESET}");
        loop {
            let line = prompt("header", "")?;
            if line.is_empty() {
                break;
            }
            let Some((name, value)) = line.split_once('=') else {
                println!("{RED}必须包含一个 =。{RESET}");
                continue;
            };
            match config::validate_header(name.trim(), value.trim()) {
                Ok(()) => {
                    config
                        .security
                        .custom_headers
                        .insert(name.trim().to_owned(), value.trim().to_owned());
                    println!("{GREEN}已加入。{RESET}");
                }
                Err(error) => println!("{RED}{error}{RESET}"),
            }
        }
        if prompt_yes_no("允许未登记客户端", false)? {
            println!("{RED}高安全运行时不允许此选项，已保持关闭。{RESET}");
        }
        config.security.allow_unregistered_clients = false;
        if prompt_yes_no("签发一个客户端凭据", false)? {
            issue_client_credential(config, config_path)?;
        }
        Ok(())
    }

    fn issue_client_credential(
        config: &mut config::AppConfig,
        config_path: &Path,
    ) -> Result<(), String> {
        if config.hosts.is_empty() {
            return Err("请先添加至少一个开机项，再签发客户端凭据".to_owned());
        }
        config.ensure_secret();
        config
            .ensure_server_identity_material()
            .map_err(|error| error.to_string())?;

        println!("\n{BOLD}{CYAN}签发便携客户端凭据{RESET}");
        println!("  {DIM}客户端身份由随机静态公钥决定；设备名只作为备注，不参与授权。{RESET}");
        let device_label = prompt("设备备注（可选，仅用于识别）", "")?;
        if device_label.chars().any(char::is_control) || device_label.len() > 128 {
            return Err("设备备注包含控制字符或超过 128 字节".to_owned());
        }

        println!(
            "  可授权主机：{}",
            config
                .hosts
                .iter()
                .map(|host| host.host_id())
                .collect::<Vec<_>>()
                .join(", ")
        );
        let selection = prompt("允许的主机 ID（逗号分隔；all=全部）", "")?;
        let allowed_hosts = if selection.trim().eq_ignore_ascii_case("all") {
            if !prompt_yes_no("确认授予该客户端全部主机权限", false)? {
                return Ok(());
            }
            config.hosts.iter().map(|host| host.host_id()).collect()
        } else {
            let known: HashSet<String> = config.hosts.iter().map(|host| host.host_id()).collect();
            let mut selected = HashSet::new();
            for value in selection
                .split(',')
                .map(str::trim)
                .filter(|value| !value.is_empty())
            {
                let id = value.to_ascii_lowercase();
                if !known.contains(&id) {
                    return Err(format!("未知主机 ID: {value}"));
                }
                selected.insert(id);
            }
            if selected.is_empty() {
                return Err("至少选择一个允许的主机 ID".to_owned());
            }
            selected.into_iter().collect()
        };

        let (static_private_key, static_public_key) = config::generate_identity_pair();
        let public_key_bytes = config::decode_key(&static_public_key)
            .map_err(|error| format!("生成客户端公钥失败: {error}"))?;
        let client_id = security::client_id_from_public_key(&public_key_bytes);
        if config
            .security
            .allowed_clients
            .iter()
            .any(|client| client.client_id.eq_ignore_ascii_case(&client_id))
            && !prompt_yes_no("该公钥 ID 已存在，轮换其凭据", false)?
        {
            return Ok(());
        }

        // The key-derived filename is portable and avoids collisions when the
        // server issues more than one bundle.  The client also accepts the fixed
        // adjacent name and a single legacy *.credential.toml file after copying.
        let default_output = client::device_credential_path(config_path, &client_id);
        let output_input = prompt("凭据输出文件", &default_output.to_string_lossy())?;
        let output = canonical_output_target(Path::new(&output_input))?;
        let server_config_target = canonical_output_target(config_path)?;
        if paths_equal(&output, &server_config_target) {
            return Err("凭据文件不能覆盖服务端配置".to_owned());
        }
        if output
            .file_name()
            .and_then(|value| value.to_str())
            .is_none_or(|value| !value.ends_with(".credential.toml"))
        {
            return Err("凭据文件名必须以 .credential.toml 结尾".to_owned());
        }
        if output
            .symlink_metadata()
            .is_ok_and(|metadata| metadata.file_type().is_symlink())
        {
            return Err("凭据输出不能是符号链接或重解析别名".to_owned());
        }
        if output.exists() && !prompt_yes_no("凭据文件已存在，覆盖并轮换", false)? {
            return Ok(());
        }

        let bundle = client::CredentialBundle {
            version: 1,
            client_id: client_id.clone(),
            device_label: device_label.trim().to_owned(),
            shared_secret: config.security.shared_secret.clone(),
            static_private_key,
            static_public_key: static_public_key.clone(),
            pinned_server_static_key: config.security.server_static_public_key.clone(),
            custom_headers: config.security.custom_headers.clone(),
        };

        // Commit the ACL first.  A failed bundle write leaves an unusable ACL
        // entry, never an entry that grants access with an unknown key.
        let mut candidate = config.clone();
        candidate
            .security
            .allowed_clients
            .retain(|client| !client.client_id.eq_ignore_ascii_case(&client_id));
        candidate
            .security
            .allowed_clients
            .push(config::AllowedClient {
                client_id: client_id.clone(),
                static_public_key,
                allowed_hosts,
            });
        candidate
            .validate()
            .map_err(|error| format!("客户端 ACL 无效: {error}"))?;
        candidate
            .save(config_path)
            .map_err(|error| format!("无法保存客户端 ACL: {error}"))?;
        client::save_credential_bundle(&output, &bundle)
            .map_err(|error| format!("无法写入客户端凭据: {error}"))?;
        *config = candidate;

        let fingerprint: String = config
            .security
            .allowed_clients
            .iter()
            .find(|client| client.client_id == client_id)
            .map(|client| {
                client
                    .static_public_key
                    .trim_start_matches("hex:")
                    .chars()
                    .take(16)
                    .collect()
            })
            .unwrap_or_else(|| "unknown".to_owned());
        println!("{GREEN}客户端凭据已签发。{RESET}");
        if device_label.trim().is_empty() {
            println!("  label       (none; portable credential)");
        } else {
            println!("  label       {}", device_label.trim());
        }
        println!("  client id   {client_id}");
        println!("  public key  {fingerprint}…");
        println!("  file        {}", output.display());
        println!(
            "  {DIM}将该私有文件复制到客户端配置目录；客户端仍只需输入服务端 IP 和端口。{RESET}"
        );
        Ok(())
    }

    fn save_server_config(config: &mut config::AppConfig, path: &Path) -> Result<(), String> {
        config.security.allow_unregistered_clients = false;
        config.client = config::ClientConfig::default();
        config.ensure_secret();
        config
            .ensure_server_identity_material()
            .map_err(|e| e.to_string())?;
        config.save(path).map_err(|e| e.to_string())?;
        println!("{GREEN}配置已原子写入 {}{RESET}", path.display());
        Ok(())
    }

    fn print_server_material(config: &config::AppConfig) {
        println!("\n{BOLD}部署信息{RESET}");
        println!(
            "  server public key : {}",
            config.security.server_static_public_key
        );
        println!("  {DIM}PSK 保存在 TOML；不要放入命令行或日志。{RESET}");
        #[cfg(unix)]
        println!("  {DIM}Linux 部署时也不要把 PSK 放入 systemd ExecStart。{RESET}");
    }

    fn print_server_deployment(
        config: &config::AppConfig,
        config_path: &Path,
    ) -> Result<(), String> {
        print_server_material(config);
        print_start_commands(config_path)
    }

    fn print_start_commands(config_path: &Path) -> Result<(), String> {
        // Deployment instructions are compile-time platform specific. A Windows
        // binary must never generate or imply a Linux service operation, and vice
        // versa.
        #[cfg(windows)]
        {
            let canonical_path = std::fs::canonicalize(config_path)
                .map_err(|error| format!("无法解析配置文件绝对路径: {error}"))?;
            let executable = std::env::current_exe()
                .and_then(std::fs::canonicalize)
                .map_err(|error| format!("无法解析当前程序绝对路径: {error}"))?;
            println!("\n{BOLD}{CYAN}Windows 前台 daemon 启动指令{RESET}");
            println!(
                "  {} --server --config {}",
                command_quote(&executable.to_string_lossy()),
                command_quote(&canonical_path.to_string_lossy())
            );
            println!(
                "  {DIM}Windows 当前以前台 daemon 运行；不要把控制台程序直接注册为 SCM 服务。"
            );
            println!(
                "  {DIM}如需服务包装器，请使用受限账户，并显式授予其对受保护配置目录的只读权限。{RESET}"
            );
            return Ok(());
        }

        #[cfg(unix)]
        {
            // Emit stable absolute paths. A service manager may use a different
            // working directory than the interactive shell.
            let canonical_path = std::fs::canonicalize(config_path)
                .map_err(|error| format!("无法解析配置文件绝对路径: {error}"))?;
            let executable = std::env::current_exe()
                .and_then(std::fs::canonicalize)
                .map_err(|error| format!("无法解析当前程序绝对路径: {error}"))?;
            let unit_config = systemd_escape(&canonical_path)?;
            println!("\n{BOLD}{CYAN}Linux 前台启动指令{RESET}");
            println!(
                "  {} --server --config {}",
                command_quote(&executable.to_string_lossy()),
                command_quote(&canonical_path.to_string_lossy())
            );
            println!("\n{BOLD}Linux systemd unit template{RESET}");
            println!(
                "  {DIM}安装程序到 /usr/local/bin，并将配置置于仅 root/服务账户可读路径。{RESET}"
            );
            println!("[Unit]");
            println!("Description=RemoteOpenPower secure Wake-on-LAN daemon");
            println!("Wants=network-online.target");
            println!("After=network-online.target");
            println!("\n[Service]");
            println!("Type=simple");
            println!("User=remote-open-power");
            println!("Group=remote-open-power");
            println!("UMask=0077");
            println!("ExecStart=/usr/local/bin/remote-open-power --server --config={unit_config}");
            println!("Restart=on-failure");
            println!("RestartSec=5s");
            println!("NoNewPrivileges=true");
            println!("CapabilityBoundingSet=");
            println!("AmbientCapabilities=");
            println!("ProtectSystem=strict");
            println!("ProtectHome=true");
            println!("PrivateTmp=true");
            println!("PrivateDevices=true");
            println!("ProtectKernelTunables=true");
            println!("ProtectKernelModules=true");
            println!("ProtectControlGroups=true");
            println!("RestrictSUIDSGID=true");
            println!("RestrictNamespaces=true");
            println!("LockPersonality=true");
            println!("MemoryDenyWriteExecute=true");
            println!("RestrictAddressFamilies=AF_INET AF_INET6");
            println!("TasksMax=96");
            println!("LimitNOFILE=256");
            println!("LimitCORE=0");
            println!("\n[Install]");
            println!("WantedBy=multi-user.target");
            return Ok(());
        }

        #[cfg(not(any(unix, windows)))]
        {
            let _ = config_path;
            Err("当前平台没有可用的服务部署模板".to_owned())
        }
    }

    fn configure_client(config_path: &Path) -> Result<(), String> {
        let mut config =
            config::AppConfig::load_unvalidated(config_path).map_err(|e| e.to_string())?;
        if !config.security.server_static_private_key.trim().is_empty() {
            return Err(
                "检测到服务端私钥；客户端必须使用独立的客户端配置文件，未覆盖原服务配置".to_owned(),
            );
        }
        print_stage("CLIENT", "安全连接与主机选择");
        config.client.address = prompt("服务端地址", &config.client.address)?;
        config.client.port = prompt_u16("服务端端口", config.client.port)?;
        if config.client.address.trim().is_empty() {
            return Err("服务端地址不能为空".to_owned());
        }
        // The client ID is derived from the portable credential's public key.
        // Keep any legacy value out of the endpoint settings so a computer-name
        // change cannot invalidate or silently replace the credential.
        config.client.client_id.clear();
        config
            .save_client_settings(config_path)
            .map_err(|error| format!("无法保存客户端设置: {error}"))?;
        // Runtime loading merges a server-issued bundle.  The bundle is kept in a
        // separate private file so the client never needs to ask for or display a
        // secret, and the server's private identity is never imported.
        let runtime = client::load_runtime(config_path, Some(config.client.address.clone()), Some(config.client.port))
        .map_err(|error| match error {
            client::ClientError::EnrollmentRequired { path } => format!(
                "未找到服务端下发凭据：{}；请先完成安全配对并放置 credential bundle（不会自动信任未知服务端）",
                path.display()
            ),
            other => other.to_string(),
        })?;
        if let Some(label) = runtime.device_label.as_deref() {
            println!("  credential label  {label}  {DIM}(仅供显示，不参与授权){RESET}");
        }
        println!(
            "  client id   {}  {DIM}(由静态公钥派生){RESET}",
            runtime.client_id
        );
        println!("{GREEN}已载入服务端签发凭据。{RESET}");
        let handle = client::spawn_client(runtime);
        let (hosts, catalog) = receive_catalog(&handle)?;
        if hosts.is_empty() {
            let _ = handle.commands.send(client::ClientCommand::Shutdown);
            println!("{YELLOW}服务端没有返回可用主机。{RESET}");
            return Ok(());
        }
        let selected = select_hosts(&hosts)?;
        if selected.is_empty() {
            let _ = handle.commands.send(client::ClientCommand::Shutdown);
            return Ok(());
        }
        run_wake_session(&handle, selected, catalog)?;
        let _ = handle.commands.send(client::ClientCommand::Shutdown);
        Ok(())
    }
}

fn receive_catalog(
    handle: &client::ClientHandle,
) -> Result<(Vec<protocol::HostSummary>, u64), String> {
    let deadline = Instant::now() + Duration::from_secs(20);
    let mut catalog: Option<(Vec<protocol::HostSummary>, u64)> = None;
    let mut status_map: HashMap<String, protocol::HostStatus> = HashMap::new();
    let mut table = None;
    let mut pending_error = None;
    loop {
        while let Ok(event) = handle.events.try_recv() {
            match event {
                client::ClientEvent::Connecting { .. } => {}
                client::ClientEvent::ConnectionFailed { code, message, .. } => {
                    pending_error = Some(format!("[{}] {message}", code.as_str()));
                }
                client::ClientEvent::Connected {
                    peer,
                    server_fingerprint,
                } => println!("{GREEN}connected{RESET} {peer}  server={server_fingerprint}"),
                client::ClientEvent::Hosts {
                    catalog_version,
                    hosts,
                } => {
                    if table.is_none() {
                        table = Some(HostTableView::new(&hosts, &status_map));
                    }
                    catalog = Some((hosts, catalog_version));
                }
                client::ClientEvent::Statuses { statuses, .. } => {
                    for status in statuses {
                        status_map.insert(status.host_id.clone(), status.clone());
                        if let Some(view) = table.as_mut() {
                            view.update(status);
                        }
                    }
                }
                client::ClientEvent::Error(error) => pending_error = Some(error),
                client::ClientEvent::Disconnected => {
                    if let Some(view) = table.as_mut() {
                        view.finish();
                    }
                    return Err("服务端已断开".to_owned());
                }
                _ => {}
            }
        }
        if let Some((hosts, catalog_version)) = &catalog
            && (hosts.is_empty() || status_map.len() >= hosts.len())
        {
            if let Some(view) = table.as_mut() {
                view.finish();
            } else {
                print_host_table(hosts, &status_map);
            }
            if let Some(error) = pending_error.take() {
                println!("{RED}{error}{RESET}");
            }
            return Ok((hosts.clone(), *catalog_version));
        }
        if Instant::now() >= deadline {
            if let Some((hosts, catalog_version)) = catalog {
                if let Some(view) = table.as_mut() {
                    view.finish();
                } else {
                    print_host_table(&hosts, &status_map);
                }
                if let Some(error) = pending_error.take() {
                    println!("{RED}{error}{RESET}");
                }
                return Ok((hosts, catalog_version));
            }
            return Err(pending_error
                .map(|error| format!("连接失败: {error}"))
                .unwrap_or_else(|| "等待主机目录超时".to_owned()));
        }
        if let Some(view) = table.as_mut() {
            let received = status_map.len();
            let total = view.host_count();
            view.set_footer(&format!("  状态: 正在获取在线状态 {received}/{total}"));
        } else {
            spinner_line("正在获取主机目录");
        }
        thread::sleep(Duration::from_millis(80));
    }
}

const HOST_ID_COLUMN: usize = 26;

struct HostTableView {
    hosts: Vec<protocol::HostSummary>,
    statuses: HashMap<String, protocol::HostStatus>,
    interactive: bool,
    rendered: bool,
    finished: bool,
    footer: String,
}

impl HostTableView {
    fn new(
        hosts: &[protocol::HostSummary],
        statuses: &HashMap<String, protocol::HostStatus>,
    ) -> Self {
        let mut view = Self {
            hosts: hosts.to_vec(),
            statuses: statuses.clone(),
            interactive: io::stdout().is_terminal(),
            rendered: false,
            finished: false,
            footer: String::new(),
        };
        if view.interactive {
            view.render();
        }
        view
    }

    fn host_count(&self) -> usize {
        self.hosts.len()
    }

    fn render(&mut self) {
        println!("\n{BOLD}{CYAN}可用主机{RESET}");
        println!("  {:>3}  {:<HOST_ID_COLUMN$}  状态", "#", "HOST ID");
        for (index, host) in self.hosts.iter().enumerate() {
            println!("{}", self.row(index, host));
        }
        self.footer = "  状态: 正在获取在线状态".to_owned();
        println!("{}", self.footer);
        self.rendered = true;
    }

    fn update(&mut self, status: protocol::HostStatus) {
        let host_id = status.host_id.clone();
        self.statuses.insert(host_id.clone(), status);
        if !self.interactive || !self.rendered {
            return;
        }
        let Some(index) = self.hosts.iter().position(|host| host.host_id == host_id) else {
            return;
        };
        let host = self.hosts[index].clone();
        let row = self.row(index, &host);
        update_line_from_bottom(self.hosts.len() + 1 - index, &row);
    }

    fn set_footer(&mut self, message: &str) {
        if self.footer == message {
            return;
        }
        self.footer = message.to_owned();
        if self.interactive && self.rendered {
            update_line_from_bottom(1, message);
        }
    }

    fn finish(&mut self) {
        if self.finished {
            return;
        }
        self.finished = true;
        if self.interactive && self.rendered {
            self.set_footer("  状态: 主机目录已就绪");
            println!();
        } else {
            print_host_table(&self.hosts, &self.statuses);
        }
    }

    fn row(&self, index: usize, host: &protocol::HostSummary) -> String {
        let state = self
            .statuses
            .get(&host.host_id)
            .map(|status| format_state(&status.state))
            .unwrap_or_else(|| format!("{DIM}UNKNOWN{RESET}"));
        format!(
            "  {:>3}  {}  {}",
            index + 1,
            cell(&host.host_id, HOST_ID_COLUMN),
            state
        )
    }
}

fn print_host_table(
    hosts: &[protocol::HostSummary],
    statuses: &HashMap<String, protocol::HostStatus>,
) {
    println!("\n{BOLD}{CYAN}可用主机{RESET}");
    println!("  {:>3}  {:<HOST_ID_COLUMN$}  状态", "#", "HOST ID");
    for (index, host) in hosts.iter().enumerate() {
        let state = statuses
            .get(&host.host_id)
            .map(|status| format_state(&status.state))
            .unwrap_or_else(|| "UNKNOWN".to_owned());
        println!(
            "  {:>3}  {}  {}",
            index + 1,
            cell(&host.host_id, HOST_ID_COLUMN),
            state
        );
    }
}

const OPERATION_HOST_COLUMN: usize = 30;

struct WakePanel {
    targets: Vec<String>,
    states: HashMap<String, String>,
    interactive: bool,
    rendered: bool,
    finished: bool,
    footer: String,
}

impl WakePanel {
    fn new(targets: &HashSet<String>, attempt: u8) -> Self {
        let mut ordered_targets: Vec<String> = targets.iter().cloned().collect();
        ordered_targets.sort();
        let states = ordered_targets
            .iter()
            .map(|target| (target.clone(), "QUEUED".to_owned()))
            .collect();
        let mut panel = Self {
            targets: ordered_targets,
            states,
            interactive: io::stdout().is_terminal(),
            rendered: false,
            finished: false,
            footer: String::new(),
        };
        if panel.interactive {
            panel.render(attempt);
        }
        panel
    }

    fn render(&mut self, attempt: u8) {
        println!("\n{BOLD}{CYAN}唤醒操作{RESET}");
        println!("  {:<OPERATION_HOST_COLUMN$}  状态", "HOST ID");
        for (index, target) in self.targets.iter().enumerate() {
            println!("{}", self.row(index, target));
        }
        self.footer = format!("  attempt={attempt}  等待服务端执行回执");
        println!("{}", self.footer);
        self.rendered = true;
    }

    fn set_state(&mut self, target: &str, state: &str) {
        if !self.states.contains_key(target) {
            return;
        }
        self.states.insert(target.to_owned(), state.to_owned());
        if !self.interactive || !self.rendered {
            return;
        }
        let Some(index) = self.targets.iter().position(|value| value == target) else {
            return;
        };
        let row = self.row(index, target);
        update_line_from_bottom(self.targets.len() + 1 - index, &row);
    }

    fn set_states<'a, I>(&mut self, targets: I, state: &str)
    where
        I: IntoIterator<Item = &'a String>,
    {
        for target in targets {
            self.set_state(target, state);
        }
    }

    fn set_footer(&mut self, message: &str) {
        if self.footer == message {
            return;
        }
        self.footer = message.to_owned();
        if self.interactive && self.rendered {
            update_line_from_bottom(1, message);
        }
    }

    fn finish(&mut self, message: &str) {
        if self.finished {
            return;
        }
        self.finished = true;
        if self.interactive && self.rendered {
            self.set_footer(message);
            println!();
        } else {
            self.print_plain();
            println!("{message}");
        }
    }

    fn print_plain(&self) {
        println!("\n{BOLD}{CYAN}唤醒操作{RESET}");
        println!("  {:<OPERATION_HOST_COLUMN$}  状态", "HOST ID");
        for (index, target) in self.targets.iter().enumerate() {
            println!("{}", self.row(index, target));
        }
    }

    fn row(&self, index: usize, target: &str) -> String {
        let state = self
            .states
            .get(target)
            .map(|value| format_operation_state(value))
            .unwrap_or_else(|| format!("{DIM}UNKNOWN{RESET}"));
        format!(
            "  {:>3}  {}  {}",
            index + 1,
            cell(target, OPERATION_HOST_COLUMN - 5),
            state
        )
    }
}

fn format_operation_state(state: &str) -> String {
    match state {
        "ONLINE" => format!("{GREEN}{state}{RESET}"),
        "SENT" => format!("{CYAN}{state}{RESET}"),
        "RETRYING" => format!("{YELLOW}{state}{RESET}"),
        "REJECTED" | "FAILED" => format!("{RED}{state}{RESET}"),
        _ => format!("{DIM}{state}{RESET}"),
    }
}

fn run_wake_session(
    handle: &client::ClientHandle,
    targets: HashSet<String>,
    catalog_version: u64,
) -> Result<(), String> {
    let operation_id = client::random_id();
    let boot_nonce = client::random_id();
    let mut panel = WakePanel::new(&targets, 1);
    if handle
        .commands
        .send(client::ClientCommand::Wake {
            host_ids: targets.iter().cloned().collect(),
            catalog_version,
            operation_id,
            boot_nonce,
            attempt: 1,
            retry_ticket: None,
        })
        .is_err()
    {
        panel.finish("  失败: 客户端 actor 已退出");
        return Err("客户端 actor 已退出".to_owned());
    }

    let mut attempt = 1u8;
    let mut ticket = None;
    let mut active_targets = targets.clone();
    let mut online = HashSet::new();
    let mut receipt = false;
    let mut receipt_deadline = Instant::now() + Duration::from_secs(15);
    let mut deadline = receipt_deadline;
    loop {
        while let Ok(event) = handle.events.try_recv() {
            match event {
                client::ClientEvent::Connecting { .. } => {}
                client::ClientEvent::ConnectionFailed { code, message, .. } => {
                    panel.finish(&format!("  失败 [{}]: {message}", code.as_str()));
                    return Err(format!("[{}] {message}", code.as_str()));
                }
                client::ClientEvent::CommandExecuted {
                    operation_id: event_operation,
                    attempt: event_attempt,
                    retry_ticket,
                    deadline_ms: _,
                    results,
                } if event_operation == operation_id && event_attempt == attempt => {
                    ticket = Some(retry_ticket);
                    receipt = true;
                    for result in &results {
                        panel.set_state(
                            &result.host_id,
                            if result.accepted { "SENT" } else { "REJECTED" },
                        );
                    }
                    active_targets = results
                        .iter()
                        .filter(|result| result.accepted)
                        .map(|result| result.host_id.clone())
                        .collect();
                    if active_targets.is_empty() {
                        panel.finish("  失败: 服务端拒绝了全部目标");
                        return Ok(());
                    }
                    // Retry timing belongs to the client. The server deadline
                    // only bounds its online observations; it must never
                    // shorten or extend either local one-minute wait window.
                    deadline = Instant::now() + WAKE_WINDOW;
                    panel.set_footer(&format!(
                        "  attempt={}  已收到执行回执 | 在线 {}/{} | 本地等待 60s",
                        attempt,
                        online.len(),
                        active_targets.len()
                    ));
                }
                client::ClientEvent::TargetOnline {
                    operation_id: event_operation,
                    attempt: event_attempt,
                    host_id,
                    ..
                } if event_operation == operation_id
                    && event_attempt == attempt
                    && active_targets.contains(&host_id) =>
                {
                    online.insert(host_id.clone());
                    panel.set_state(&host_id, "ONLINE");
                }
                client::ClientEvent::Error(error) => {
                    panel.set_footer(&format!("  {RED}错误: {error}{RESET}"));
                }
                client::ClientEvent::Disconnected => {
                    panel.finish("  失败: 服务端已断开");
                    return Err("服务端已断开".to_owned());
                }
                _ => {}
            }
        }
        if !active_targets.is_empty() && online.len() == active_targets.len() {
            panel.finish("  {GREEN}{BOLD}完成: 全部目标已上线{RESET}");
            return Ok(());
        }
        if !receipt && Instant::now() >= receipt_deadline {
            panel.finish("  {RED}失败: 等待服务端执行回执超时{RESET}");
            return Ok(());
        }
        if receipt && Instant::now() >= deadline {
            if attempt == 1 {
                let Some(retry_ticket) = ticket else {
                    panel.finish("  {RED}失败: 服务端未返回 retry ticket{RESET}");
                    return Err("服务端未返回 retry ticket".to_owned());
                };
                panel.set_states(targets.iter(), "RETRYING");
                if handle
                    .commands
                    .send(client::ClientCommand::Wake {
                        host_ids: targets.iter().cloned().collect(),
                        catalog_version,
                        operation_id,
                        boot_nonce,
                        attempt: 2,
                        retry_ticket: Some(retry_ticket),
                    })
                    .is_err()
                {
                    panel.finish("  {RED}失败: 客户端 actor 已退出{RESET}");
                    return Err("客户端 actor 已退出".to_owned());
                }
                attempt = 2;
                receipt = false;
                online.clear();
                active_targets = targets.clone();
                receipt_deadline = Instant::now() + Duration::from_secs(15);
                deadline = receipt_deadline;
                panel.set_footer("  attempt=2  一分钟未全部上线，已按授权票据重试");
            } else {
                panel.finish("  {RED}失败: 两次等待均超时{RESET}");
                return Ok(());
            }
        }
        let remaining = if receipt {
            deadline.saturating_duration_since(Instant::now()).as_secs()
        } else {
            receipt_deadline
                .saturating_duration_since(Instant::now())
                .as_secs()
        };
        panel.set_footer(&format!(
            "  attempt={}  在线 {}/{}  剩余={}s",
            attempt,
            online.len(),
            active_targets.len(),
            remaining
        ));
        let _ = receipt; // receipt is retained to make the state transition explicit.
        thread::sleep(Duration::from_millis(100));
    }
}

fn run_client_cli(cli: &Cli) -> Result<(), String> {
    let runtime = client::load_runtime(&cli.config, cli.address.clone(), cli.port)
        .map_err(|e| e.to_string())?;
    if let Some(label) = runtime.device_label.as_deref() {
        println!("  credential label  {label}  {DIM}(仅供显示，不参与授权){RESET}");
    }
    let handle = client::spawn_client(runtime);
    if cli.wake.is_empty() {
        let _ = receive_catalog(&handle)?;
        let _ = handle.commands.send(client::ClientCommand::Shutdown);
        return Ok(());
    }
    let wanted: HashSet<String> = cli
        .wake
        .iter()
        .map(|value| value.trim().to_ascii_lowercase())
        .collect();
    let (hosts, catalog) = receive_catalog(&handle)?;
    let available: HashSet<String> = hosts.iter().map(|host| host.host_id.clone()).collect();
    if !wanted.is_subset(&available) {
        let _ = handle.commands.send(client::ClientCommand::Shutdown);
        return Err("--wake 包含不在服务端目录中的主机 ID".to_owned());
    }
    run_wake_session(&handle, wanted, catalog)?;
    let _ = handle.commands.send(client::ClientCommand::Shutdown);
    Ok(())
}

fn spinner_line(message: &str) {
    static TICK: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let tick = TICK.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    print!(
        "\r\x1b[2K{CYAN}{}{RESET} {}",
        SPINNER[tick % SPINNER.len()],
        message
    );
    let _ = io::stdout().flush();
}

fn update_line_from_bottom(lines_up: usize, text: &str) {
    if lines_up == 0 || !io::stdout().is_terminal() {
        return;
    }
    print!("\x1b[s\x1b[{}A\r\x1b[2K{}\x1b[u", lines_up, text);
    let _ = io::stdout().flush();
}

fn cell(value: &str, width: usize) -> String {
    let mut output: String = value.chars().take(width).collect();
    if value.chars().count() > width && width >= 3 {
        output = value.chars().take(width - 3).collect();
        output.push_str("...");
    }
    format!("{output:<width$}")
}

fn format_state(state: &protocol::HostState) -> String {
    match state {
        protocol::HostState::Online | protocol::HostState::Succeeded => {
            format!("{GREEN}ONLINE{RESET}")
        }
        protocol::HostState::Waking => format!("{YELLOW}WAKING{RESET}"),
        protocol::HostState::Offline => format!("{RED}OFFLINE{RESET}"),
        protocol::HostState::Failed => format!("{RED}FAILED{RESET}"),
        protocol::HostState::Unknown => format!("{DIM}UNKNOWN{RESET}"),
    }
}
