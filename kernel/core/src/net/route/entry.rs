// SPDX-License-Identifier: MPL-2.0

use aster_bigtcp::wire::{Ipv4Address, Ipv4Cidr, Ipv6Address, Ipv6AddressExt, Ipv6Cidr};

use super::RouteLookupKey;
use crate::{net::iface::Iface, prelude::*};

/// A route that describes how to handle packets for a destination network.
#[derive(Clone)]
pub(super) struct RouteEntry<A: RouteAddressFamily> {
    dst: A::Cidr,
    gateway: Option<A>,
    output_iface: Arc<Iface>,
    table_id: RouteTableId,
    metric: RouteMetric,
    type_: RouteType,
    origin: RouteOrigin<A>,
}

/// Where a route came from and how it reaches its destination.
///
/// Reference: <https://elixir.bootlin.com/linux/v7.1/source/include/uapi/linux/rtnetlink.h>.
#[derive(Clone, Copy)]
pub(super) struct RouteOrigin<A: RouteAddressFamily> {
    pub(super) protocol: RouteProtocol,
    pub(super) scope: RouteScope,
    pub(super) preferred_source: Option<A>,
}

impl<A: RouteAddressFamily> RouteEntry<A> {
    /// Creates a route entry.
    pub(super) fn new(
        dst: A::Cidr,
        gateway: Option<A>,
        output_iface: Arc<Iface>,
        table_id: RouteTableId,
        metric: RouteMetric,
        type_: RouteType,
        origin: RouteOrigin<A>,
    ) -> Result<Self> {
        if dst != A::network(&dst) {
            return_errno_with_message!(Errno::EINVAL, "the route destination is not canonical");
        }

        Ok(Self {
            dst,
            gateway,
            output_iface,
            table_id,
            metric,
            type_,
            origin,
        })
    }

    /// Returns the destination network.
    pub(super) const fn dst(&self) -> &A::Cidr {
        &self.dst
    }

    /// Returns the next-hop gateway.
    pub(super) const fn gateway(&self) -> Option<A> {
        self.gateway
    }

    /// Returns the output interface.
    pub(super) const fn output_iface(&self) -> &Arc<Iface> {
        &self.output_iface
    }

    /// Returns the ID of the table containing the route.
    pub(super) const fn table_id(&self) -> RouteTableId {
        self.table_id
    }

    /// Returns the route metric.
    pub(super) const fn metric(&self) -> RouteMetric {
        self.metric
    }

    /// Returns the route type.
    pub(super) const fn type_(&self) -> RouteType {
        self.type_
    }

    /// Returns the origin of the route.
    pub(super) const fn origin(&self) -> &RouteOrigin<A> {
        &self.origin
    }

    /// Whether both entries describe the same route through the same interface.
    pub(super) fn is_same_route(&self, other: &Self) -> bool {
        self.has_same_key(other)
            && self.gateway == other.gateway
            && self.type_ == other.type_
            && self.origin.protocol == other.origin.protocol
            && self.origin.scope == other.origin.scope
            && self.origin.preferred_source == other.origin.preferred_source
    }

    /// Whether both entries occupy the same slot of the same routing table.
    pub(super) fn has_same_key(&self, other: &Self) -> bool {
        self.table_id == other.table_id
            && self.dst == other.dst
            && self.metric == other.metric
            && self.output_iface.index() == other.output_iface.index()
    }

    pub(super) fn matches_lookup(&self, key: &RouteLookupKey<A>) -> bool {
        A::contains(&self.dst, key.dst())
            && (!key.direct || self.gateway.is_none() && self.origin.scope.get() >= RouteScope::LINK.get())
    }
}

/// An IP address family supported by the routing manager.
pub(super) trait RouteAddressFamily: Copy + Eq + Ord {
    /// The CIDR type associated with this address family.
    type Cidr: Copy + Eq + Ord;

    /// Returns whether `cidr` contains `address`.
    fn contains(cidr: &Self::Cidr, address: &Self) -> bool;

    /// Returns the canonical network represented by `cidr`.
    fn network(cidr: &Self::Cidr) -> Self::Cidr;

    /// Returns the prefix length of `cidr`.
    fn prefix_len(cidr: &Self::Cidr) -> u8;
}

impl RouteAddressFamily for Ipv4Address {
    type Cidr = Ipv4Cidr;

    fn contains(cidr: &Self::Cidr, address: &Self) -> bool {
        cidr.contains_addr(address)
    }

    fn network(cidr: &Self::Cidr) -> Self::Cidr {
        cidr.network()
    }

    fn prefix_len(cidr: &Self::Cidr) -> u8 {
        cidr.prefix_len()
    }
}

impl RouteAddressFamily for Ipv6Address {
    type Cidr = Ipv6Cidr;

    fn contains(cidr: &Self::Cidr, address: &Self) -> bool {
        cidr.contains_addr(address)
    }

    fn network(cidr: &Self::Cidr) -> Self::Cidr {
        Ipv6Cidr::new(
            cidr.address().mask(cidr.prefix_len()).into(),
            cidr.prefix_len(),
        )
    }

    fn prefix_len(cidr: &Self::Cidr) -> u8 {
        cidr.prefix_len()
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(in crate::net) struct RouteTableId(u32);

impl RouteTableId {
    /// The table ID of the default table,
    /// which is reserved for routes used after earlier rules do not match.
    pub(in crate::net) const DEFAULT: Self = Self(253);
    /// The table ID of the main table.
    pub(in crate::net) const MAIN: Self = Self(254);
    /// The table ID of the local table,
    /// which manages routes for addresses assigned locally.
    pub(in crate::net) const LOCAL: Self = Self(255);

    /// Creates the ID of a table; zero stands for the main table.
    pub(in crate::net) const fn new(id: u32) -> Self {
        if id == 0 { Self::MAIN } else { Self(id) }
    }

    pub(in crate::net) const fn get(self) -> u32 {
        self.0
    }
}

/// A route metric used to prefer routes with equal prefix lengths;
/// lower values have higher priority.
#[derive(Clone, Copy, Debug, Default, Eq, Ord, PartialEq, PartialOrd)]
pub(in crate::net) struct RouteMetric(u32);

impl RouteMetric {
    pub(super) const MIN: Self = Self(0);

    pub(in crate::net) const fn new(value: u32) -> Self {
        Self(value)
    }

    pub(in crate::net) const fn get(self) -> u32 {
        self.0
    }
}

/// The protocol that installed a route (`RTPROT_*`).
///
/// Reference: <https://elixir.bootlin.com/linux/v7.1/source/include/uapi/linux/rtnetlink.h>.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::net) struct RouteProtocol(u8);

impl RouteProtocol {
    /// Installed by the kernel.
    pub(in crate::net) const KERNEL: Self = Self(2);

    pub(in crate::net) const fn new(value: u8) -> Self {
        Self(value)
    }

    pub(in crate::net) const fn get(self) -> u8 {
        self.0
    }
}

/// The distance to the destination of a route (`RT_SCOPE_*`).
///
/// Reference: <https://elixir.bootlin.com/linux/v7.1/source/include/uapi/linux/rtnetlink.h>.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::net) struct RouteScope(u8);

impl RouteScope {
    /// Reachable through a gateway.
    pub(in crate::net) const UNIVERSE: Self = Self(0);
    /// Reachable on the attached link.
    pub(in crate::net) const LINK: Self = Self(253);
    /// Reachable on this host.
    pub(in crate::net) const HOST: Self = Self(254);

    pub(in crate::net) const fn new(value: u8) -> Self {
        Self(value)
    }

    pub(in crate::net) const fn get(self) -> u8 {
        self.0
    }
}

/// The forwarding behavior of a route.
///
/// Reference: <https://elixir.bootlin.com/linux/v7.1/source/include/uapi/linux/rtnetlink.h>.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::net) enum RouteType {
    /// Forwards packets to a destination.
    Unicast = 1,
    /// Delivers packets locally.
    Local = 2,
    /// Delivers IPv4 broadcasts.
    Broadcast = 3,
}
