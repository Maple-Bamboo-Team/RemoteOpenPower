//! Bounded target availability probes.
//!
//! A probe is observational only; it never grants authority and its result is
//! always tied to the operation/session that requested it by the server actor.

use crate::config::HostConfig;
use std::{
    net::{IpAddr, SocketAddr, SocketAddrV6, TcpStream},
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};

#[cfg(not(windows))]
use std::path::Path;
#[cfg(windows)]
use std::{ffi::OsString, os::windows::ffi::OsStringExt, path::PathBuf};

#[cfg(windows)]
#[link(name = "kernel32")]
unsafe extern "system" {
    fn GetSystemDirectoryW(buffer: *mut u16, size: u32) -> u32;
}

pub trait StatusProbe: Send + Sync {
    fn is_online(&self, host: &HostConfig) -> bool;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct PlatformStatusProbe;

impl StatusProbe for PlatformStatusProbe {
    fn is_online(&self, host: &HostConfig) -> bool {
        let timeout = Duration::from_millis(host.probe_timeout_ms.clamp(100, 5_000));
        let deadline = Instant::now() + timeout;
        let ip = match host.ip.parse::<IpAddr>() {
            Ok(value) => value,
            Err(_) => return false,
        };

        // A TCP probe is useful when ICMP is filtered.  Ports are fixed or
        // explicitly configured; the client cannot turn this into a scanner.
        let ports: Vec<u16> = if host.probe_port != 0 {
            vec![host.probe_port]
        } else {
            vec![22, 80, 443, 445, 3389, 5900]
        };
        // TCP and ICMP share one total host budget.  Without this split a
        // failed TCP sweep followed by ping could consume twice the configured
        // timeout and multiply that cost across a status fanout.
        let tcp_budget = timeout / 2;
        let per_probe = tcp_budget / ports.len() as u32;
        for port in ports {
            if TcpStream::connect_timeout(
                &scoped_socket_addr(ip, port, host.wol_ipv6_interface),
                per_probe,
            )
            .is_ok()
            {
                return true;
            }
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        remaining >= Duration::from_millis(50) && fixed_ping(ip, host.wol_ipv6_interface, remaining)
    }
}

fn scoped_socket_addr(ip: IpAddr, port: u16, interface: u32) -> SocketAddr {
    match ip {
        IpAddr::V6(value) if value.is_unicast_link_local() => {
            SocketAddr::V6(SocketAddrV6::new(value, port, 0, interface))
        }
        _ => SocketAddr::new(ip, port),
    }
}

fn scoped_ip_argument(ip: IpAddr, interface: u32) -> String {
    match ip {
        IpAddr::V6(value) if value.is_unicast_link_local() => format!("{value}%{interface}"),
        _ => ip.to_string(),
    }
}

fn fixed_ping(ip: IpAddr, interface: u32, timeout: Duration) -> bool {
    // Never resolve an executable through PATH in a long-running daemon.
    // PATH is process/environment input and can be controlled by a local
    // unprivileged user in poorly hardened service configurations.
    #[cfg(windows)]
    let ping_path = match trusted_windows_ping_path() {
        Some(path) => path,
        None => return false,
    };
    #[cfg(not(windows))]
    let ping_path = if Path::new("/usr/bin/ping").is_file() {
        Path::new("/usr/bin/ping")
    } else {
        Path::new("/bin/ping")
    };
    if !ping_path.is_file() {
        return false;
    }
    let mut command = Command::new(&ping_path);
    command.env_clear();
    #[cfg(windows)]
    if let Some(directory) = ping_path.parent() {
        command.current_dir(directory);
    }
    #[cfg(not(windows))]
    command.current_dir("/");
    command
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    #[cfg(windows)]
    {
        let target = scoped_ip_argument(ip, interface);
        command.args(["-n", "1", "-w", &timeout.as_millis().to_string(), &target]);
    }
    #[cfg(not(windows))]
    {
        let seconds = timeout.as_secs().max(1).to_string();
        let target = scoped_ip_argument(ip, interface);
        command.args(["-c", "1", "-W", &seconds, &target]);
    }
    let mut child = match command.spawn() {
        Ok(value) => value,
        Err(_) => return false,
    };
    let deadline = Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return status.success(),
            Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(20)),
            Ok(None) => {
                terminate_child(&mut child, "probe timeout");
                return false;
            }
            Err(_) => {
                terminate_child(&mut child, "probe wait failure");
                return false;
            }
        }
    }
}

fn terminate_child(child: &mut Child, context: &'static str) {
    if let Err(error) = child.kill()
        && error.kind() != std::io::ErrorKind::InvalidInput
    {
        crate::logging::log(
            crate::logging::Level::Warn,
            format!("probe child termination failed context={context} error={error}"),
        );
    }
    if let Err(error) = child.wait() {
        crate::logging::log(
            crate::logging::Level::Warn,
            format!("probe child reap failed context={context} error={error}"),
        );
    }
}

#[cfg(windows)]
fn trusted_windows_ping_path() -> Option<PathBuf> {
    // Query Windows itself instead of trusting the mutable SystemRoot
    // environment variable of a service process.
    let mut buffer = vec![0u16; 32_768];
    let length = unsafe { GetSystemDirectoryW(buffer.as_mut_ptr(), buffer.len() as u32) } as usize;
    if length == 0 || length >= buffer.len() {
        return None;
    }
    let directory = PathBuf::from(OsString::from_wide(&buffer[..length]));
    Some(directory.join("PING.EXE"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn link_local_probe_coordinates_preserve_the_interface_scope() {
        let ip: IpAddr = "fe80::1234".parse().unwrap();
        let SocketAddr::V6(address) = scoped_socket_addr(ip, 9, 17) else {
            panic!("link-local destination must remain IPv6");
        };
        assert_eq!(address.scope_id(), 17);
        assert_eq!(scoped_ip_argument(ip, 17), "fe80::1234%17");
    }
}
