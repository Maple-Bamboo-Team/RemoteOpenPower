//! Platform WoL adapter.
//!
//! The `wol` crate builds the standards-compliant magic packet and writes it
//! through a caller-owned UDP socket.  No shell, script, driver or arbitrary
//! executable is involved.

use crate::config::{HostConfig, parse_mac};
use std::{
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6, UdpSocket},
};
use thiserror::Error;
use wol::{MacAddress, SendMagicPacket};

#[derive(Debug, Error)]
pub enum WakeError {
    #[error("invalid configured target")]
    InvalidTarget,
    #[error("UDP sender unavailable")]
    Io(#[from] io::Error),
}

pub trait WakeSender: Send + Sync {
    fn wake(&self, host: &HostConfig) -> Result<(), WakeError>;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct PlatformWakeSender;

impl WakeSender for PlatformWakeSender {
    fn wake(&self, host: &HostConfig) -> Result<(), WakeError> {
        let mac = parse_mac(&host.mac).map_err(|_| WakeError::InvalidTarget)?;
        let ip: IpAddr = host.ip.parse().map_err(|_| WakeError::InvalidTarget)?;
        match ip {
            IpAddr::V4(_) => {
                let socket = UdpSocket::bind(SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 0))?;
                socket.set_broadcast(true)?;
                socket.send_magic_packet(
                    MacAddress::from(mac),
                    None,
                    SocketAddr::new(Ipv4Addr::BROADCAST.into(), host.wol_port),
                )?;
                Ok(())
            }
            IpAddr::V6(value) => send_ipv6_magic_packet(mac, value, host),
        }
    }
}

const IPV6_ALL_NODES: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1);

fn send_ipv6_magic_packet(
    mac: [u8; 6],
    target: Ipv6Addr,
    host: &HostConfig,
) -> Result<(), WakeError> {
    let socket = UdpSocket::bind(SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), 0))?;
    let packet = MacAddress::from(mac);
    let [unicast, multicast] = ipv6_destinations(target, host.wol_port, host.wol_ipv6_interface);
    let unicast_result = socket.send_magic_packet(packet, None, unicast);
    let multicast_result = (|| {
        let socket_ref = socket2::SockRef::from(&socket);
        socket_ref.set_multicast_loop_v6(false)?;
        socket_ref.set_multicast_hops_v6(1)?;
        if host.wol_ipv6_interface != 0 {
            socket_ref.set_multicast_if_v6(host.wol_ipv6_interface)?;
        }
        socket.send_magic_packet(packet, None, multicast)
    })();
    match (unicast_result, multicast_result) {
        (Ok(()), _) | (_, Ok(())) => Ok(()),
        (Err(unicast), Err(multicast)) => Err(WakeError::Io(io::Error::new(
            multicast.kind(),
            format!("IPv6 WoL unicast failed ({unicast}); multicast failed ({multicast})"),
        ))),
    }
}

fn ipv6_destinations(target: Ipv6Addr, port: u16, interface: u32) -> [SocketAddr; 2] {
    let unicast_scope = if target.is_unicast_link_local() {
        interface
    } else {
        0
    };
    [
        SocketAddr::V6(SocketAddrV6::new(target, port, 0, unicast_scope)),
        SocketAddr::V6(SocketAddrV6::new(IPV6_ALL_NODES, port, 0, interface)),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipv6_magic_packet_destinations_include_unicast_and_all_nodes() {
        let host = HostConfig {
            hostname: "lab".into(),
            display_name: String::new(),
            mac: "02:11:22:33:44:55".into(),
            ip: "fd00::10".into(),
            wol_port: 9,
            probe_timeout_ms: 1_000,
            probe_port: 0,
            wol_ipv6_interface: 7,
        };
        let target: Ipv6Addr = "fd00::10".parse().unwrap();
        let [unicast, multicast] =
            ipv6_destinations(target, host.wol_port, host.wol_ipv6_interface);
        assert_eq!(unicast, SocketAddr::new(target.into(), 9));
        let SocketAddr::V6(multicast) = multicast else {
            panic!("multicast destination must be IPv6");
        };
        assert_eq!(*multicast.ip(), IPV6_ALL_NODES);
        assert_eq!(multicast.port(), 9);
        assert_eq!(multicast.scope_id(), 7);
    }

    #[test]
    fn link_local_unicast_uses_the_configured_interface_scope() {
        let target: Ipv6Addr = "fe80::1234".parse().unwrap();
        let [unicast, _] = ipv6_destinations(target, 9, 12);
        let SocketAddr::V6(unicast) = unicast else {
            panic!("unicast destination must be IPv6");
        };
        assert_eq!(unicast.scope_id(), 12);
    }
}
