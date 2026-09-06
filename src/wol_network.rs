use super::Ipv4Interface;
use std::{
    io,
    net::{Ipv4Addr, UdpSocket},
};

#[cfg(windows)]
pub(super) fn ipv4_interfaces() -> io::Result<Vec<Ipv4Interface>> {
    use std::{
        mem::{align_of, size_of},
        ptr,
    };
    use windows_sys::Win32::{
        Foundation::{ERROR_BUFFER_OVERFLOW, ERROR_NO_DATA, NO_ERROR},
        NetworkManagement::{
            IpHelper::{
                GAA_FLAG_SKIP_ANYCAST, GAA_FLAG_SKIP_DNS_SERVER, GAA_FLAG_SKIP_FRIENDLY_NAME,
                GAA_FLAG_SKIP_MULTICAST, GetAdaptersAddresses, IF_TYPE_PPP,
                IF_TYPE_PPPMULTILINKBUNDLE, IF_TYPE_SOFTWARE_LOOPBACK, IF_TYPE_TUNNEL,
                IP_ADAPTER_ADDRESSES_LH,
            },
            Ndis::IfOperStatusUp,
        },
        Networking::WinSock::{AF_INET, IpDadStatePreferred, SOCKADDR_IN},
    };
    const _: () = assert!(align_of::<IP_ADAPTER_ADDRESSES_LH>() <= align_of::<u64>());
    let mut size = 15 * 1024;
    // The native list points into this aligned allocation. Retry a bounded
    // number of times if adapters change between sizing and enumeration.
    for _ in 0..4 {
        if size as usize > 1024 * 1024 {
            return Err(io::Error::other("IPv4 interface inventory exceeds 1 MiB"));
        }
        let mut storage = vec![0u64; (size as usize).div_ceil(size_of::<u64>())];
        let head = storage.as_mut_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>();
        let result = unsafe {
            GetAdaptersAddresses(
                u32::from(AF_INET),
                GAA_FLAG_SKIP_ANYCAST
                    | GAA_FLAG_SKIP_MULTICAST
                    | GAA_FLAG_SKIP_DNS_SERVER
                    | GAA_FLAG_SKIP_FRIENDLY_NAME,
                ptr::null(),
                head,
                &mut size,
            )
        };
        match result {
            ERROR_BUFFER_OVERFLOW => continue,
            ERROR_NO_DATA => return Ok(Vec::new()),
            NO_ERROR => {}
            error => return Err(io::Error::from_raw_os_error(error as i32)),
        }
        let mut interfaces = Vec::new();
        let mut current = head;
        while !current.is_null() {
            let adapter = unsafe { &*current };
            let index = unsafe { adapter.Anonymous1.Anonymous.IfIndex };
            let broadcast = !matches!(
                adapter.IfType,
                IF_TYPE_SOFTWARE_LOOPBACK
                    | IF_TYPE_PPP
                    | IF_TYPE_PPPMULTILINKBUNDLE
                    | IF_TYPE_TUNNEL
            );
            let mut address = adapter.FirstUnicastAddress;
            while !address.is_null() {
                let unicast = unsafe { &*address };
                if !unicast.Address.lpSockaddr.is_null()
                    && unicast.Address.iSockaddrLength as usize >= size_of::<SOCKADDR_IN>()
                    && unsafe { (*unicast.Address.lpSockaddr).sa_family } == AF_INET
                {
                    let socket_address =
                        unsafe { &*unicast.Address.lpSockaddr.cast::<SOCKADDR_IN>() };
                    let prefix = u32::from(unicast.OnLinkPrefixLength);
                    let mask = u32::MAX
                        .checked_shl(32u32.saturating_sub(prefix))
                        .unwrap_or(0);
                    interfaces.push(Ipv4Interface {
                        index,
                        address: Ipv4Addr::from(
                            unsafe { socket_address.sin_addr.S_un.S_addr }.to_ne_bytes(),
                        ),
                        netmask: Ipv4Addr::from(mask),
                        up: adapter.OperStatus == IfOperStatusUp
                            && unicast.DadState == IpDadStatePreferred
                            && prefix <= 32,
                        broadcast,
                    });
                }
                address = unicast.Next;
            }
            current = adapter.Next;
        }
        return Ok(interfaces);
    }
    Err(io::Error::other(
        "IPv4 interface inventory kept changing during enumeration",
    ))
}

#[cfg(unix)]
pub(super) fn ipv4_interfaces() -> io::Result<Vec<Ipv4Interface>> {
    use std::ptr;
    struct Addresses(*mut libc::ifaddrs);
    impl Drop for Addresses {
        fn drop(&mut self) {
            unsafe { libc::freeifaddrs(self.0) };
        }
    }
    let mut head = ptr::null_mut();
    if unsafe { libc::getifaddrs(&mut head) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let addresses = Addresses(head);
    let mut current = addresses.0;
    let mut interfaces = Vec::new();
    while !current.is_null() {
        let interface = unsafe { &*current };
        if !interface.ifa_addr.is_null()
            && !interface.ifa_netmask.is_null()
            && !interface.ifa_name.is_null()
            && i32::from(unsafe { (*interface.ifa_addr).sa_family }) == libc::AF_INET
        {
            let index = unsafe { libc::if_nametoindex(interface.ifa_name) };
            if index == 0 {
                return Err(io::Error::last_os_error());
            }
            let address = unsafe { &*interface.ifa_addr.cast::<libc::sockaddr_in>() };
            let mask = unsafe { &*interface.ifa_netmask.cast::<libc::sockaddr_in>() };
            let flags = interface.ifa_flags as i32;
            interfaces.push(Ipv4Interface {
                index,
                address: Ipv4Addr::from(address.sin_addr.s_addr.to_ne_bytes()),
                netmask: Ipv4Addr::from(mask.sin_addr.s_addr.to_ne_bytes()),
                up: flags & (libc::IFF_UP | libc::IFF_RUNNING) == libc::IFF_UP | libc::IFF_RUNNING,
                broadcast: flags & libc::IFF_BROADCAST != 0
                    && flags & (libc::IFF_LOOPBACK | libc::IFF_POINTOPOINT) == 0,
            });
        }
        current = interface.ifa_next;
    }
    Ok(interfaces)
}

pub(super) fn bind_ipv4_interface(socket: &UdpSocket, index: u32) -> io::Result<()> {
    // IP_UNICAST_IF uses a network-order interface index on both Windows and
    // Linux. Unlike SO_BINDTODEVICE this does not need CAP_NET_RAW on Linux.
    let index = index.to_be();
    #[cfg(windows)]
    {
        use std::os::windows::io::AsRawSocket;
        use windows_sys::Win32::Networking::WinSock::{
            IP_UNICAST_IF, IPPROTO_IP, SOCKET_ERROR, WSAGetLastError, setsockopt,
        };
        if unsafe {
            setsockopt(
                socket.as_raw_socket() as _,
                IPPROTO_IP,
                IP_UNICAST_IF,
                (&index as *const u32).cast(),
                std::mem::size_of_val(&index) as i32,
            )
        } == SOCKET_ERROR
        {
            return Err(io::Error::from_raw_os_error(unsafe { WSAGetLastError() }));
        }
    }
    #[cfg(unix)]
    {
        use std::os::fd::AsRawFd;
        if unsafe {
            libc::setsockopt(
                socket.as_raw_fd(),
                libc::IPPROTO_IP,
                libc::IP_UNICAST_IF,
                (&index as *const u32).cast(),
                std::mem::size_of_val(&index) as libc::socklen_t,
            )
        } != 0
        {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

#[cfg(test)]
pub(super) fn bound_ipv4_interface(socket: &UdpSocket) -> io::Result<u32> {
    let mut index = 0u32;
    #[cfg(windows)]
    {
        use std::os::windows::io::AsRawSocket;
        use windows_sys::Win32::Networking::WinSock::{
            IP_UNICAST_IF, IPPROTO_IP, SOCKET_ERROR, WSAGetLastError, getsockopt,
        };
        let mut length = std::mem::size_of_val(&index) as i32;
        if unsafe {
            getsockopt(
                socket.as_raw_socket() as _,
                IPPROTO_IP,
                IP_UNICAST_IF,
                (&mut index as *mut u32).cast(),
                &mut length,
            )
        } == SOCKET_ERROR
        {
            return Err(io::Error::from_raw_os_error(unsafe { WSAGetLastError() }));
        }
    }
    #[cfg(unix)]
    {
        use std::os::fd::AsRawFd;
        let mut length = std::mem::size_of_val(&index) as libc::socklen_t;
        if unsafe {
            libc::getsockopt(
                socket.as_raw_fd(),
                libc::IPPROTO_IP,
                libc::IP_UNICAST_IF,
                (&mut index as *mut u32).cast(),
                &mut length,
            )
        } != 0
        {
            return Err(io::Error::last_os_error());
        }
    }
    // Winsock returns host order even though setsockopt accepts network order.
    #[cfg(unix)]
    let index = u32::from_be(index);
    Ok(index)
}
