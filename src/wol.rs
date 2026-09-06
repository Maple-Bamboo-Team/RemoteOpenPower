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

#[path = "wol_network.rs"]
mod network;

#[derive(Debug, Error)]
pub enum WakeError {
    #[error("invalid configured target")]
    InvalidTarget,
    #[error("UDP sender unavailable: {0}")]
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
            IpAddr::V4(value) => send_ipv4_magic_packet(mac, value, host.wol_port),
            IpAddr::V6(value) => send_ipv6_magic_packet(mac, value, host),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Ipv4Interface {
    index: u32,
    address: Ipv4Addr,
    netmask: Ipv4Addr,
    up: bool,
    broadcast: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Ipv4Route {
    interface: u32,
    source: Ipv4Addr,
    broadcast: Ipv4Addr,
    prefix_len: u32,
}

fn select_ipv4_route(target: Ipv4Addr, interfaces: &[Ipv4Interface]) -> io::Result<Ipv4Route> {
    let mut selected: Option<Ipv4Route> = None;
    let mut ambiguous = false;
    for interface in interfaces {
        if !interface.up
            || !interface.broadcast
            || interface.index == 0
            || interface.address.is_unspecified()
            || interface.address.is_loopback()
            || interface.address.is_multicast()
            || interface.address.is_broadcast()
        {
            continue;
        }
        let mask = u32::from(interface.netmask);
        let prefix_len = mask.leading_ones();
        if prefix_len == 0 || prefix_len + mask.trailing_zeros() != 32 {
            continue;
        }
        let subnet = u32::from(interface.address) & mask;
        if u32::from(target) & mask != subnet {
            continue;
        }
        let candidate = Ipv4Route {
            interface: interface.index,
            source: interface.address,
            broadcast: Ipv4Addr::from(subnet | !mask),
            prefix_len,
        };
        match selected.as_mut() {
            None => selected = Some(candidate),
            Some(best) if candidate.prefix_len > best.prefix_len => {
                *best = candidate;
                ambiguous = false;
            }
            Some(best) if candidate.prefix_len == best.prefix_len => {
                if candidate.interface != best.interface {
                    ambiguous = true;
                } else if candidate.source < best.source {
                    *best = candidate;
                }
            }
            Some(_) => {}
        }
    }
    let route = selected.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::AddrNotAvailable,
            format!(
                "no active broadcast-capable IPv4 interface shares the subnet of target {target}"
            ),
        )
    })?;
    if ambiguous {
        return Err(io::Error::new(
            io::ErrorKind::AddrNotAvailable,
            format!(
                "multiple IPv4 interfaces equally match target {target}/{}; resolve overlapping interface subnets",
                route.prefix_len
            ),
        ));
    }
    let mask = u32::MAX << (32 - route.prefix_len);
    if route.prefix_len >= 31
        || u32::from(target) == u32::from(route.source) & mask
        || target == route.broadcast
        || route.broadcast.is_broadcast()
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "target {target}/{} has no usable host-directed broadcast subnet",
                route.prefix_len
            ),
        ));
    }
    Ok(route)
}

fn ipv4_socket(route: Ipv4Route) -> io::Result<UdpSocket> {
    let context = |error: io::Error| {
        io::Error::new(
            error.kind(),
            format!(
                "cannot bind IPv4 WoL source={} interface={}: {error}",
                route.source, route.interface
            ),
        )
    };
    let socket = UdpSocket::bind((route.source, 0)).map_err(context)?;
    network::bind_ipv4_interface(&socket, route.interface).map_err(context)?;
    socket.set_broadcast(true)?;
    Ok(socket)
}

fn send_ipv4_magic_packet(mac: [u8; 6], target: Ipv4Addr, port: u16) -> Result<(), WakeError> {
    let interfaces = network::ipv4_interfaces().map_err(|error| {
        io::Error::new(
            error.kind(),
            format!("cannot enumerate IPv4 interfaces: {error}"),
        )
    })?;
    let route = select_ipv4_route(target, &interfaces)?;
    let socket = ipv4_socket(route)?;
    let destination = SocketAddr::new(route.broadcast.into(), port);
    let source = socket.local_addr()?;
    socket
        .send_magic_packet(MacAddress::from(mac), None, destination)
        .map_err(|error| {
            io::Error::new(
                error.kind(),
                format!(
                    "IPv4 WoL failed target={target} interface={} source={source} destination={destination}: {error}",
                    route.interface
                ),
            )
        })?;
    crate::logging::log(
        crate::logging::Level::Info,
        format!(
            "IPv4 WoL sent target={target} interface={} source={source} destination={destination}",
            route.interface
        ),
    );
    Ok(())
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

    fn interface(index: u32, address: &str, netmask: &str) -> Ipv4Interface {
        Ipv4Interface {
            index,
            address: address.parse().unwrap(),
            netmask: netmask.parse().unwrap(),
            up: true,
            broadcast: true,
        }
    }

    #[test]
    fn ipv4_selects_target_lan_instead_of_first_virtual_adapter() {
        let real = interface(19, "192.168.0.5", "255.255.255.0");
        let virtual_adapter = interface(9, "192.168.56.1", "255.255.255.0");
        for inventory in [[virtual_adapter, real], [real, virtual_adapter]] {
            let route = select_ipv4_route("192.168.0.20".parse().unwrap(), &inventory).unwrap();
            assert_eq!(route.interface, 19);
            assert_eq!(route.source, real.address);
            assert_eq!(
                route.broadcast,
                "192.168.0.255".parse::<Ipv4Addr>().unwrap()
            );
        }
    }

    #[test]
    fn ipv4_broadcast_uses_actual_non_24_netmask() {
        for (source, mask, target, broadcast, prefix) in [
            (
                "10.20.1.5",
                "255.255.0.0",
                "10.20.200.8",
                "10.20.255.255",
                16,
            ),
            (
                "192.168.2.5",
                "255.255.254.0",
                "192.168.3.10",
                "192.168.3.255",
                23,
            ),
            (
                "192.168.0.130",
                "255.255.255.128",
                "192.168.0.150",
                "192.168.0.255",
                25,
            ),
            ("10.0.0.1", "255.255.255.252", "10.0.0.2", "10.0.0.3", 30),
        ] {
            let route =
                select_ipv4_route(target.parse().unwrap(), &[interface(1, source, mask)]).unwrap();
            assert_eq!(route.broadcast, broadcast.parse::<Ipv4Addr>().unwrap());
            assert_eq!(route.prefix_len, prefix);
        }
    }

    #[test]
    fn ipv4_longest_prefix_wins_independently_of_enumeration_order() {
        let broad = interface(1, "10.20.1.5", "255.255.0.0");
        let narrow = interface(2, "10.20.2.5", "255.255.255.0");
        let other_broad = interface(3, "10.20.3.5", "255.255.0.0");
        for inventory in [[broad, other_broad, narrow], [narrow, broad, other_broad]] {
            let route = select_ipv4_route("10.20.2.10".parse().unwrap(), &inventory).unwrap();
            assert_eq!(route.interface, 2);
        }
    }

    #[test]
    fn ipv4_equal_prefix_interfaces_are_ambiguous_but_aliases_are_not() {
        let first = interface(1, "192.168.0.5", "255.255.255.0");
        let other_interface = interface(2, "192.168.0.6", "255.255.255.0");
        let target = "192.168.0.10".parse().unwrap();
        let error = select_ipv4_route(target, &[first, other_interface]).unwrap_err();
        assert!(error.to_string().contains("multiple IPv4 interfaces"));
        let alias = interface(1, "192.168.0.6", "255.255.255.0");
        for inventory in [[first, alias], [alias, first]] {
            assert_eq!(
                select_ipv4_route(target, &inventory).unwrap().source,
                first.address
            );
        }
    }

    #[test]
    fn ipv4_no_match_never_falls_back_to_global_broadcast() {
        let target = "192.168.0.20".parse().unwrap();
        assert!(select_ipv4_route(target, &[]).is_err());
        assert!(
            select_ipv4_route(target, &[interface(9, "192.168.56.1", "255.255.255.0")]).is_err()
        );
        assert!(select_ipv4_route(target, &[interface(1, "192.168.0.5", "0.0.0.0")]).is_err());
        assert!(select_ipv4_route(target, &[interface(1, "192.168.0.5", "128.0.0.0")]).is_err());
    }

    #[test]
    fn ipv4_rejects_inactive_nonbroadcast_and_invalid_interface_rows() {
        let valid = interface(19, "192.168.0.5", "255.255.255.0");
        for invalid in [
            Ipv4Interface { up: false, ..valid },
            Ipv4Interface {
                broadcast: false,
                ..valid
            },
            Ipv4Interface { index: 0, ..valid },
            interface(19, "192.168.0.5", "255.0.255.0"),
            interface(19, "0.0.0.0", "255.255.255.0"),
            interface(19, "127.0.0.1", "255.0.0.0"),
        ] {
            assert!(select_ipv4_route("192.168.0.20".parse().unwrap(), &[invalid]).is_err());
        }
    }

    #[test]
    fn ipv4_rejects_network_broadcast_and_point_to_point_targets() {
        for (source, mask, target) in [
            ("192.168.0.5", "255.255.255.0", "192.168.0.0"),
            ("192.168.0.5", "255.255.255.0", "192.168.0.255"),
            ("10.0.0.0", "255.255.255.254", "10.0.0.1"),
            ("10.0.0.1", "255.255.255.255", "10.0.0.1"),
        ] {
            assert!(
                select_ipv4_route(target.parse().unwrap(), &[interface(1, source, mask)]).is_err()
            );
        }
    }

    #[test]
    fn native_ipv4_inventory_and_socket_binding_send_no_packets() {
        let interfaces = network::ipv4_interfaces().unwrap();
        for interface in interfaces
            .iter()
            .filter(|interface| interface.up && interface.broadcast)
        {
            let route = select_ipv4_route(interface.address, &[*interface]);
            if let Ok(route) = route {
                let socket = ipv4_socket(route).unwrap();
                assert_eq!(socket.local_addr().unwrap().ip(), IpAddr::V4(route.source));
                assert!(socket.broadcast().unwrap());
                assert_eq!(
                    network::bound_ipv4_interface(&socket).unwrap(),
                    route.interface
                );
                println!(
                    "IPv4 route source={} interface={} broadcast={}/{}",
                    route.source, route.interface, route.broadcast, route.prefix_len
                );
            }
        }
    }

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
