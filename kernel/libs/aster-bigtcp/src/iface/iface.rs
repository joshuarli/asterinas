// SPDX-License-Identifier: MPL-2.0

use alloc::{sync::Arc, vec::Vec};

use smoltcp::{
    iface::Route,
    wire::{EthernetAddress, Ipv4Address, Ipv4Cidr, Ipv6Cidr},
};

use super::{
    BindPortConfig, BoundTcpPort, InterfaceFlags, InterfaceName, InterfaceType,
    LinkTap, IpTap,
};
use crate::{
    errors::{AddressTableFull, BindError, LinkSendError, RouteTableFull},
    ext::Ext,
};

/// The effective IPv4 path MTU and whether its route requires fragmentation.
#[derive(Clone, Copy)]
pub struct PathMtu {
    pub mtu: usize,
    pub locked: bool,
}

/// The route whose path MTU applies to a destination.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PathMtuRoute {
    Default,
    Table { table: u32, gateway: Option<Ipv4Address> },
}

/// A network interface.
///
/// A network interface (abbreviated as iface) is a hardware or software component that connects a
/// computer to a network. Network interfaces can be physical components like Ethernet ports or
/// wireless adapters. They can also be virtual interfaces created by software, such as virtual
/// private network (VPN) connections.
pub trait Iface<E>: internal::IfaceInternal<E> + Send + Sync {
    /// Returns the Ethernet address, if the interface uses Ethernet framing.
    fn ethernet_addr(&self) -> Option<EthernetAddress>;

    /// Transmits or receives packets queued in the iface, and updates socket status accordingly.
    fn poll(&self);

    /// Returns the maximum transmission unit.
    fn mtu(&self) -> usize;

    /// Forgets the link-layer addresses learned from neighbors.
    fn flush_neighbors(&self);

    /// Sends a link-layer frame that starts with an Ethernet header.
    ///
    /// The taps other than `origin` see the frame as an outgoing one. An interface without
    /// link-layer framing sends the payload of the frame and receives it again.
    fn send_link_frame(
        &self,
        frame: &[u8],
        origin: Option<&Arc<dyn LinkTap>>,
    ) -> Result<(), LinkSendError>;
}

impl<E: Ext> dyn Iface<E> {
    // FIXME: The reason for binding the socket and the iface together is because there are
    // limitations inside smoltcp. See discussion at
    // <https://github.com/smoltcp-rs/smoltcp/issues/779>.

    /// Binds a TCP port to the iface.
    ///
    /// If no specific port is given in [`BindPortConfig`], the iface will pick up an ephemeral
    /// port.
    pub fn bind_tcp(
        self: &Arc<Self>,
        config: BindPortConfig,
    ) -> Result<BoundTcpPort<E>, BindError> {
        let common = self.common();
        common.bind_tcp(self.clone(), config)
    }

    /// Returns the interface index.
    pub fn index(&self) -> u32 {
        self.common().index()
    }

    /// Gets the name of the iface.
    ///
    /// In Linux, the name is usually the driver name followed by a unit number.
    pub fn name(&self) -> &InterfaceName {
        self.common().name()
    }

    /// Registers an observer of the link-layer frames of the iface.
    pub fn add_link_tap(&self, tap: Arc<dyn LinkTap>) {
        self.common().add_link_tap(tap)
    }

    /// Unregisters an observer of the link-layer frames of the iface.
    pub fn remove_link_tap(&self, tap: &Arc<dyn LinkTap>) {
        self.common().remove_link_tap(tap)
    }

    /// Registers an observer of locally delivered IP packets.
    pub fn add_ip_tap(&self, tap: Arc<dyn IpTap>) { self.common().add_ip_tap(tap); }
    /// Unregisters an IP packet observer.
    pub fn remove_ip_tap(&self, tap: &Arc<dyn IpTap>) { self.common().remove_ip_tap(tap); }
    /// Enqueues a complete IPv4 packet for routed transmission using the given path MTU.
    pub fn send_ipv4_packet(&self, packet: &[u8], mtu: usize) -> Result<(), LinkSendError> {
        self.common().send_ipv4_packet(packet, mtu)
    }

    /// Returns the interface type.
    pub fn type_(&self) -> InterfaceType {
        self.common().type_()
    }

    /// Returns the interface flags.
    pub fn flags(&self) -> InterfaceFlags {
        self.common().flags()
    }

    /// Brings the interface up or down.
    ///
    /// A down interface drops the packets it receives and sends none.
    ///
    /// Taking an interface down also forgets the neighbors it has learned, as Linux does.
    pub fn set_administratively_up(&self, up: bool) {
        self.common().set_administratively_up(up);
        if !up {
            self.flush_neighbors();
        }
    }

    // FIXME: Linux and smoltcp allow multiple IP CIDRs per interface, while the
    // address-related APIs below only account for the first CIDR of each family.

    /// Gets the IPv4 CIDR of the iface, if any.
    pub fn ipv4_cidr(&self) -> Option<Ipv4Cidr> {
        self.common().ipv4_cidr()
    }

    /// Gets all IPv4 CIDRs of the iface, primary addresses first.
    pub fn ipv4_cidrs(&self) -> Vec<Ipv4Cidr> {
        self.common().ipv4_cidrs()
    }

    /// Replaces the IPv4 CIDRs of the iface.
    ///
    /// The first CIDR is the one the iface uses as its source address when it must pick one.
    pub fn set_ipv4_cidrs(&self, cidrs: &[Ipv4Cidr]) -> Result<(), AddressTableFull> {
        self.common().set_ipv4_cidrs(cidrs)
    }

    /// Replaces the IPv4 routes through a gateway that the iface uses to reach other networks.
    ///
    /// Destinations on a network of one of the iface's addresses are always reached directly.
    pub fn set_ipv4_gateway_routes(
        &self,
        routes: &[(Ipv4Cidr, Ipv4Address)],
    ) -> Result<(), RouteTableFull> {
        self.common().set_ipv4_gateway_routes(routes)
    }

    /// Gets the IPv6 CIDR of the iface, if any.
    pub fn ipv6_cidr(&self) -> Option<Ipv6Cidr> {
        self.common().ipv6_cidr()
    }

    /// Gets the IPv4 broadcast address of the iface, if any.
    ///
    /// IPv6 does not define broadcast addresses and uses multicast instead.
    pub fn broadcast_addr(&self) -> Option<Ipv4Address> {
        self.common().ipv4_cidr()?.broadcast()
    }

    /// Clears learned path MTUs after a routing policy change.
    pub fn clear_path_mtu(&self) { self.common().clear_path_mtu(); }

    /// Returns the cached IPv4 path MTU, bounded by the interface MTU.
    pub fn path_mtu(&self, destination: smoltcp::wire::IpAddress) -> PathMtu {
        self.common().path_mtu(destination, self.mtu())
    }

    /// Returns the cached path MTU for the selected route.
    pub fn path_mtu_for_route(&self, destination: smoltcp::wire::IpAddress, route: PathMtuRoute) -> PathMtu {
        self.common().path_mtu_for_route(destination, route, self.mtu())
    }

    /// Returns routes currently installed in the interface.
    pub fn routes(&self) -> Vec<Route> {
        self.common().routes()
    }

    /// Returns a reference to the associated [`ScheduleNextPoll`].
    ///
    /// [`ScheduleNextPoll`]: crate::iface::sched::ScheduleNextPoll
    pub fn sched_poll(&self) -> &E::ScheduleNextPoll {
        self.common().sched_poll()
    }
}

pub(super) mod internal {
    use crate::{ext::Ext, iface::common::IfaceCommon};

    /// An internal trait that abstracts the common part of different ifaces.
    pub trait IfaceInternal<E> {
        fn common(&self) -> &IfaceCommon<E>
        where
            E: Ext;
    }
}
