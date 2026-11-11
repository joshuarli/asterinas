// SPDX-License-Identifier: MPL-2.0

use aster_bigtcp::{
    iface::{InterfaceFlags, InterfaceName, InterfaceType},
    wire::{EthernetAddress, Ipv4Address, Ipv4Cidr},
};
use ostd::{mm::VmIo, task::Task};

use crate::{
    dispatch_ioctl,
    net::{
        iface::{DEFAULT_TX_QUEUE_LEN, Iface, config, iter_all_ifaces},
        route::{Ipv4RouteSelector, NewIpv4Route, NewRouteAction, RouteType},
        socket::{
            Socket,
            netlink::RequestOrigin,
            util::options::check_current_privileged,
        },
    },
    prelude::*,
    util::{ioctl::RawIoctl, net::CSocketAddrFamily},
};

mod ioctl_defs {
    use super::{CIfConf, CIfReq, CRtEntry};
    use crate::{
        ioc,
        util::ioctl::{InData, InOutData},
    };

    // Reference: <https://elixir.bootlin.com/linux/v7.1/source/include/uapi/linux/sockios.h#L56>.
    pub(super) type GetIfName       = ioc!(SIOCGIFNAME,     0x8910, InOutData<CIfReq>);
    pub(super) type GetIfConf       = ioc!(SIOCGIFCONF,     0x8912, InOutData<CIfConf>);
    pub(super) type GetIfFlags      = ioc!(SIOCGIFFLAGS,    0x8913, InOutData<CIfReq>);
    pub(super) type SetIfFlags      = ioc!(SIOCSIFFLAGS,    0x8914, InOutData<CIfReq>);
    pub(super) type SetIfAddr       = ioc!(SIOCSIFADDR,     0x8916, InOutData<CIfReq>);
    pub(super) type SetIfNetmask    = ioc!(SIOCSIFNETMASK,  0x891C, InOutData<CIfReq>);
    pub(super) type GetIfMetric     = ioc!(SIOCGIFMETRIC,   0x891D, InOutData<CIfReq>);
    pub(super) type GetIfMtu        = ioc!(SIOCGIFMTU,      0x8921, InOutData<CIfReq>);
    pub(super) type GetIfHwAddr     = ioc!(SIOCGIFHWADDR,   0x8927, InOutData<CIfReq>);
    pub(super) type GetIfIndex      = ioc!(SIOCGIFINDEX,    0x8933, InOutData<CIfReq>);
    pub(super) type GetIfTxQueueLen = ioc!(SIOCGIFTXQLEN,   0x8942, InOutData<CIfReq>);
    pub(super) type AddRoute        = ioc!(SIOCADDRT,       0x890B, InData<CRtEntry>);
    pub(super) type DeleteRoute     = ioc!(SIOCDELRT,       0x890C, InData<CRtEntry>);
}

pub(crate) fn socket_ioctl<T: Socket>(socket: &T, raw_ioctl: RawIoctl) -> Result<i32> {
    // Linux always handles `SIOCGIFCONF` first.
    match handle_get_ifconf(raw_ioctl) {
        Err(err) if err.error() == Errno::ENOTTY => (),
        res => return res,
    }

    // Each socket handles commands specific to its protocol or socket type.
    match socket.protocol_ioctl(raw_ioctl) {
        Err(err) if err.error() == Errno::ENOTTY => {}
        res => return res,
    }

    // Handle network device commands.
    network_device_ioctl(raw_ioctl)
}

fn handle_get_ifconf(raw_ioctl: RawIoctl) -> Result<i32> {
    use ioctl_defs::*;

    dispatch_ioctl!(match raw_ioctl {
        cmd @ GetIfConf => {
            let mut ifconf = cmd.read()?;
            ifconf.write_ifreqs()?;
            cmd.write(&ifconf)?;
            Ok(0)
        }
        _ => return_errno_with_message!(Errno::ENOTTY, "the socket ioctl command is unknown"),
    })
}

fn network_device_ioctl(raw_ioctl: RawIoctl) -> Result<i32> {
    use ioctl_defs::*;

    dispatch_ioctl!(match raw_ioctl {
        cmd @ GetIfName => {
            let mut ifreq = cmd.read()?;
            let iface = ifreq.get_iface_by_index()?;
            ifreq.name = *iface.name();
            cmd.write(&ifreq)?;
            Ok(0)
        }
        cmd @ GetIfFlags => {
            let mut ifreq = cmd.read()?;
            let iface = ifreq.get_iface_by_name()?;
            ifreq.data = CIfReqData::new_flags(iface.flags().bits() as i16);
            cmd.write(&ifreq)?;
            Ok(0)
        }
        cmd @ SetIfFlags => {
            check_current_privileged()?;
            let ifreq = cmd.read()?;
            set_iface_flags(&ifreq)?;
            Ok(0)
        }
        cmd @ SetIfAddr => {
            check_current_privileged()?;
            let ifreq = cmd.read()?;
            set_iface_address(&ifreq)?;
            Ok(0)
        }
        cmd @ SetIfNetmask => {
            check_current_privileged()?;
            let ifreq = cmd.read()?;
            set_iface_netmask(&ifreq)?;
            Ok(0)
        }
        cmd @ AddRoute => {
            check_current_privileged()?;
            let rtentry = cmd.read()?;
            add_route(&rtentry)?;
            Ok(0)
        }
        cmd @ DeleteRoute => {
            check_current_privileged()?;
            let rtentry = cmd.read()?;
            delete_route(&rtentry)?;
            Ok(0)
        }
        cmd @ GetIfMetric => {
            let mut ifreq = cmd.read()?;
            ifreq.get_iface_by_name()?;
            // Linux's per-interface metric is currently unused and always reported as zero.
            ifreq.data = CIfReqData::new_value(0);
            cmd.write(&ifreq)?;
            Ok(0)
        }
        cmd @ GetIfMtu => {
            let mut ifreq = cmd.read()?;
            let iface = ifreq.get_iface_by_name()?;
            ifreq.data = CIfReqData::new_mtu(iface.mtu() as i32);
            cmd.write(&ifreq)?;
            Ok(0)
        }
        cmd @ GetIfHwAddr => {
            let mut ifreq = cmd.read()?;
            let iface = ifreq.get_iface_by_name()?;
            let socket_addr = CSocketAddr::new_ethernet(iface.type_(), iface.ethernet_addr());
            ifreq.data = CIfReqData::new_hardware_addr(socket_addr);
            cmd.write(&ifreq)?;
            Ok(0)
        }
        cmd @ GetIfIndex => {
            let mut ifreq = cmd.read()?;
            let iface = ifreq.get_iface_by_name()?;
            let index = iface.index();
            ifreq.data = CIfReqData::new_value(index.cast_signed());
            cmd.write(&ifreq)?;
            Ok(0)
        }
        cmd @ GetIfTxQueueLen => {
            let mut ifreq = cmd.read()?;
            ifreq.get_iface_by_name()?;
            ifreq.data = CIfReqData::new_value(DEFAULT_TX_QUEUE_LEN.cast_signed());
            cmd.write(&ifreq)?;
            Ok(0)
        }
        _ => return_errno_with_message!(Errno::ENOTTY, "the socket ioctl command is unknown"),
    })
}

/// Applies the requested flags of `SIOCSIFFLAGS`.
fn set_iface_flags(ifreq: &CIfReq) -> Result<()> {
    let ifreq = *ifreq;
    let iface = ifreq.get_iface_by_name()?;
    let requested = InterfaceFlags::from_bits_truncate(u32::from(*ifreq.data.flags() as u16));
    config::change_flags(iface, requested)
}

/// Applies `SIOCSIFADDR`.
///
/// Like Linux, the address' class determines the prefix length, and a broadcast device also gets
/// the broadcast address of that network.
fn set_iface_address(ifreq: &CIfReq) -> Result<()> {
    let ifreq = *ifreq;
    let address = ifreq.data.addr().ipv4()?;
    let iface = ifreq.get_iface_by_name()?;
    if iface.flags().contains(InterfaceFlags::POINTOPOINT) {
        return_errno_with_message!(
            Errno::EOPNOTSUPP,
            "point-to-point interfaces are not supported"
        );
    }

    let prefix_len = classful_prefix_len(address).ok_or_else(|| {
        Error::with_message(Errno::EINVAL, "the address has no classful network")
    })?;
    let cidr = Ipv4Cidr::new(address, prefix_len);
    let broadcast = if iface.flags().contains(InterfaceFlags::BROADCAST) && prefix_len < 31 {
        Some(config::broadcast_address(cidr))
    } else {
        None
    };
    let scope = if address.octets()[0] == 127 {
        RT_SCOPE_HOST
    } else {
        RT_SCOPE_UNIVERSE
    };

    config::replace_labeled_ipv4_address(
        iface,
        &ifreq.name,
        config::NewAddress {
            cidr,
            broadcast,
            label: Some(ifreq.name),
            scope,
        },
        RequestOrigin::KERNEL,
    )
}

/// Applies `SIOCSIFNETMASK`.
fn set_iface_netmask(ifreq: &CIfReq) -> Result<()> {
    let ifreq = *ifreq;
    let mask = ifreq.data.netmask().ipv4()?;
    let iface = ifreq.get_iface_by_name()?;
    if !config::ipv4_addresses(iface)
        .iter()
        .any(|address| address.label() == &ifreq.name)
    {
        return_errno_with_message!(
            Errno::EADDRNOTAVAIL,
            "the interface does not have the address"
        );
    }
    let prefix_len = mask_prefix_len(mask)
        .ok_or_else(|| Error::with_message(Errno::EINVAL, "the netmask is not contiguous"))?;

    config::set_labeled_ipv4_netmask(iface, &ifreq.name, prefix_len, RequestOrigin::KERNEL)
}

/// The classful prefix length of an address, as `inet_abc_len` computes for `SIOCSIFADDR`.
fn classful_prefix_len(address: Ipv4Address) -> Option<u8> {
    let value = u32::from_be_bytes(address.octets());
    if address.octets()[0] == 0 || value == u32::MAX {
        return Some(0);
    }

    if value & 0x8000_0000 == 0 {
        Some(8)
    } else if value & 0xC000_0000 == 0x8000_0000 {
        Some(16)
    } else if value & 0xE000_0000 == 0xC000_0000 {
        Some(24)
    } else if value & 0xF000_0000 == 0xE000_0000 {
        Some(32)
    } else {
        None
    }
}

/// The prefix length of a contiguous netmask, or `None` when the mask is not contiguous.
fn mask_prefix_len(mask: Ipv4Address) -> Option<u8> {
    let value = u32::from_be_bytes(mask.octets());
    if is_bad_mask(value) {
        return None;
    }
    Some(value.leading_ones() as u8)
}

/// Whether a host-order netmask is not contiguous, as Linux's `bad_mask` decides.
fn is_bad_mask(mask: u32) -> bool {
    let wildcard = !mask;
    wildcard & wildcard.wrapping_add(1) != 0
}

/// Installs the route of `SIOCADDRT`.
fn add_route(rtentry: &CRtEntry) -> Result<()> {
    let route = parse_route(rtentry, true)?;
    config::add_ipv4_route(
        NewIpv4Route {
            action: NewRouteAction::Send(RouteType::Unicast),
            table: route.table,
            destination: route.destination,
            gateway: route.gateway,
            iface_index: route.iface_index,
            priority: route.priority,
            protocol: RTPROT_BOOT,
            scope: route.scope,
        },
        RequestOrigin::KERNEL,
    )
}

/// Removes the route of `SIOCDELRT`.
fn delete_route(rtentry: &CRtEntry) -> Result<()> {
    let route = parse_route(rtentry, false)?;
    config::remove_ipv4_route(
        &Ipv4RouteSelector {
            table: route.table,
            destination: route.destination,
            priority: Some(route.priority).filter(|priority| *priority != 0),
            gateway: route.gateway,
            iface_index: route.iface_index,
            protocol: None,
            type_: Some(RTN_UNICAST),
            scope: Some(route.scope).filter(|scope| *scope != RT_SCOPE_NOWHERE),
        },
        RequestOrigin::KERNEL,
    )
}

struct ParsedRoute {
    table: u32,
    destination: Ipv4Cidr,
    gateway: Option<Ipv4Address>,
    iface_index: Option<u32>,
    priority: u32,
    scope: u8,
}

/// Translates `struct rtentry` into the route that the netlink path also installs.
///
/// Reference: `rtentry_to_fib_config` in
/// <https://elixir.bootlin.com/linux/v7.1/source/net/ipv4/fib_frontend.c>.
fn parse_route(rtentry: &CRtEntry, adding: bool) -> Result<ParsedRoute> {
    if rtentry.dst.family != CSocketAddrFamily::AF_INET as u16 {
        return_errno_with_message!(
            Errno::EAFNOSUPPORT,
            "the route destination is not an IPv4 address"
        );
    }
    if rtentry.flags & RTF_REJECT != 0 {
        return_errno_with_message!(Errno::EOPNOTSUPP, "reject routes are not supported");
    }
    if rtentry.flags & (RTF_MTU | RTF_WINDOW | RTF_IRTT) != 0 {
        return_errno_with_message!(Errno::EOPNOTSUPP, "route metrics are not supported");
    }

    let address = rtentry.dst.ipv4_unchecked();
    let mut prefix_len = 32;
    if rtentry.flags & RTF_HOST == 0 {
        let mask = rtentry.genmask.ipv4_unchecked();
        if rtentry.genmask.family != CSocketAddrFamily::AF_INET as u16
            && (rtentry.genmask.family != 0 || !mask.is_unspecified())
        {
            return_errno_with_message!(
                Errno::EAFNOSUPPORT,
                "the route netmask is not an IPv4 address"
            );
        }

        let mask_bits = u32::from_be_bytes(mask.octets());
        if u32::from_be_bytes(address.octets()) & !mask_bits != 0 {
            return_errno_with_message!(Errno::EINVAL, "the route destination has host bits set");
        }
        if is_bad_mask(mask_bits) {
            return_errno_with_message!(Errno::EINVAL, "the route netmask is not contiguous");
        }
        prefix_len = mask_bits.leading_ones() as u8;
    }

    let iface_index = match read_device_name(rtentry.dev)? {
        Some(name) => Some(
            iter_all_ifaces()
                .find(|iface| iface.name() == &name)
                .ok_or_else(|| Error::with_message(Errno::ENODEV, "no interface found"))?
                .index(),
        ),
        None => None,
    };

    let gateway = (rtentry.gateway.family == CSocketAddrFamily::AF_INET as u16)
        .then(|| rtentry.gateway.ipv4_unchecked())
        .filter(|gateway| !gateway.is_unspecified());
    if adding && rtentry.flags & RTF_GATEWAY != 0 && gateway.is_none() {
        return_errno_with_message!(Errno::EINVAL, "a gateway route needs a gateway");
    }

    let scope = if rtentry.flags & RTF_GATEWAY != 0 && gateway.is_some() {
        RT_SCOPE_UNIVERSE
    } else if adding {
        RT_SCOPE_LINK
    } else {
        RT_SCOPE_NOWHERE
    };
    let priority = if rtentry.metric > 0 {
        rtentry.metric as u32 - 1
    } else {
        0
    };

    Ok(ParsedRoute {
        table: RT_TABLE_MAIN,
        destination: Ipv4Cidr::new(address, prefix_len),
        gateway,
        iface_index,
        priority,
        scope,
    })
}

/// Reads the interface name that `rt_dev` points to, as `rtentry_to_fib_config` does.
fn read_device_name(dev: Vaddr) -> Result<Option<InterfaceName>> {
    const IFNAMSIZ: usize = 16;

    if dev == 0 {
        return Ok(None);
    }

    let task = Task::current().unwrap();
    let user_space = CurrentUserSpace::new(task.as_thread_local().unwrap());
    let mut name = [0u8; IFNAMSIZ - 1];
    user_space.read_bytes(dev, &mut name)?;
    if name.contains(&b':') {
        return_errno_with_message!(Errno::EOPNOTSUPP, "interface aliases are not supported");
    }

    Ok(Some(InterfaceName::from_bytes_until_nul(&name)))
}

/// `RTF_GATEWAY` in Linux.
const RTF_GATEWAY: u16 = 0x0002;
/// `RTF_HOST` in Linux.
const RTF_HOST: u16 = 0x0004;
/// `RTF_MTU` in Linux.
const RTF_MTU: u16 = 0x0040;
/// `RTF_WINDOW` in Linux.
const RTF_WINDOW: u16 = 0x0080;
/// `RTF_IRTT` in Linux.
const RTF_IRTT: u16 = 0x0100;
/// `RTF_REJECT` in Linux.
const RTF_REJECT: u16 = 0x0200;

/// `RTPROT_BOOT` in Linux, the protocol that `SIOCADDRT` installs a route with.
const RTPROT_BOOT: u8 = 3;
/// `RT_TABLE_MAIN` in Linux.
const RT_TABLE_MAIN: u32 = 254;
/// `RT_SCOPE_UNIVERSE` in Linux.
const RT_SCOPE_UNIVERSE: u8 = 0;
/// `RT_SCOPE_LINK` in Linux.
const RT_SCOPE_LINK: u8 = 253;
/// `RT_SCOPE_HOST` in Linux.
const RT_SCOPE_HOST: u8 = 254;
/// `RT_SCOPE_NOWHERE` in Linux, which removes a route of any scope.
const RT_SCOPE_NOWHERE: u8 = 255;
/// `RTN_UNICAST` in Linux.
const RTN_UNICAST: u8 = 1;

/// `struct rtentry` in Linux.
///
/// Reference: <https://elixir.bootlin.com/linux/v7.1/source/include/uapi/linux/route.h#L31>.
#[padding_struct]
#[repr(C)]
#[derive(Clone, Copy, Pod)]
struct CRtEntry {
    pad1: Vaddr,
    dst: CSocketAddr,
    gateway: CSocketAddr,
    genmask: CSocketAddr,
    flags: u16,
    pad2: i16,
    pad3: Vaddr,
    pad4: Vaddr,
    metric: i16,
    dev: Vaddr,
    mtu: Vaddr,
    window: Vaddr,
    irtt: u16,
}

/// `struct ifconf` in Linux.
///
/// Reference: <https://elixir.bootlin.com/linux/v7.1/source/include/uapi/linux/if.h#L286>.
#[padding_struct]
#[repr(C)]
#[derive(Clone, Copy, Pod)]
struct CIfConf {
    len: i32,
    data: Vaddr,
}

impl CIfConf {
    fn write_ifreqs(&mut self) -> Result<()> {
        let ifreqs = iter_all_ifaces()
            .flat_map(config::ipv4_addresses)
            .map(|address| CIfReq {
                name: *address.label(),
                data: CIfReqData::new_addr(CSocketAddr::new_ipv4(address.address())),
            });

        if self.data == 0 {
            let count = ifreqs.count();
            self.len = (count * size_of::<CIfReq>()) as i32;
            return Ok(());
        }

        let task = Task::current().unwrap();
        let user_space = CurrentUserSpace::new(task.as_thread_local().unwrap());
        let mut writer = user_space.writer(self.data, self.len.max(0) as usize)?;

        let max_ifreqs = writer.avail() / size_of::<CIfReq>();
        let mut count = 0;
        for ifreq in ifreqs.take(max_ifreqs) {
            writer.write_val(&ifreq)?;
            count += 1;
        }
        self.len = (count * size_of::<CIfReq>()) as i32;

        Ok(())
    }
}

/// `struct ifreq` in Linux.
///
/// Reference: <https://elixir.bootlin.com/linux/v7.1/source/include/uapi/linux/if.h#L234>.
#[repr(C)]
#[derive(Clone, Copy, Pod)]
pub(in crate::net::socket) struct CIfReq {
    name: InterfaceName,
    data: CIfReqData,
}

/// The `ifr_ifru` union in `struct ifreq` in Linux.
///
/// Reference: <https://elixir.bootlin.com/linux/v7.1/source/include/uapi/linux/if.h#L241>.
#[pod_union]
#[repr(C)]
#[derive(Clone, Copy)]
union CIfReqData {
    addr: CSocketAddr,
    dst_addr: CSocketAddr,
    broad_addr: CSocketAddr,
    netmask: CSocketAddr,
    hardware_addr: CSocketAddr,
    flags: i16,
    value: i32,
    mtu: i32,
    map: CIfMap,
    slave: InterfaceName,
    new_name: InterfaceName,
    data: Vaddr,
    settings: CIfSettings,
}

/// `struct sockaddr` in Linux.
///
/// Reference: <https://elixir.bootlin.com/linux/v7.1/source/include/linux/socket.h#L36>.
#[repr(C)]
#[derive(Clone, Copy, Pod)]
struct CSocketAddr {
    family: u16,
    data: [u8; 14],
}

impl CSocketAddr {
    fn ipv4(&self) -> Result<Ipv4Address> {
        if self.family != CSocketAddrFamily::AF_INET as u16 {
            return_errno_with_message!(Errno::EINVAL, "the address family is not AF_INET");
        }
        Ok(self.ipv4_unchecked())
    }

    fn ipv4_unchecked(&self) -> Ipv4Address {
        Ipv4Address::new(self.data[2], self.data[3], self.data[4], self.data[5])
    }

    fn new_ipv4(ipv4_addr: Ipv4Address) -> Self {
        let family = CSocketAddrFamily::AF_INET as u16;

        let mut data = [0u8; 14];
        data[2..6].copy_from_slice(&ipv4_addr.octets());

        Self { family, data }
    }

    fn new_ethernet(iface_type: InterfaceType, ether_addr: Option<EthernetAddress>) -> Self {
        let family = iface_type as u16;

        let mut data = [0u8; 14];
        if let Some(ether_addr) = ether_addr {
            data[..6].copy_from_slice(&ether_addr.0)
        }

        Self { family, data }
    }
}

/// `struct if_settings` in Linux.
///
/// Reference: <https://elixir.bootlin.com/linux/v7.1/source/include/uapi/linux/if.h#L207>.
#[repr(C)]
#[derive(Clone, Copy, Pod)]
struct CIfSettings {
    type_: u32,
    size: u32,
    data: Vaddr,
}

/// `struct ifmap` in Linux.
///
/// Reference: <https://elixir.bootlin.com/linux/v7.1/source/include/uapi/linux/if.h#L196>.
#[padding_struct]
#[repr(C)]
#[derive(Clone, Copy, Pod)]
struct CIfMap {
    mem_start: Vaddr,
    mem_end: Vaddr,
    base_addr: u16,
    irq: u8,
    dma: u8,
    port: u8,
}

impl CIfReq {
    pub(in crate::net::socket) fn set_sockaddr_ipv4(&mut self, ipv4_addr: Ipv4Address) {
        let socket_addr = CSocketAddr::new_ipv4(ipv4_addr);
        self.data = CIfReqData::new_addr(socket_addr);
    }

    pub(in crate::net::socket) fn get_iface_by_name(&self) -> Result<&'static Arc<Iface>> {
        iter_all_ifaces()
            .find(|iface| iface.name() == &self.name)
            .ok_or_else(|| Error::with_message(Errno::ENODEV, "no interface found"))
    }

    fn get_iface_by_index(&self) -> Result<&'static Arc<Iface>> {
        let index = *self.data.value();
        iter_all_ifaces()
            .find(|iface| iface.index().cast_signed() == index)
            .ok_or_else(|| Error::with_message(Errno::ENODEV, "no interface found"))
    }
}
