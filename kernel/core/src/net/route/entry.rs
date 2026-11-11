// SPDX-License-Identifier: MPL-2.0

use aster_bigtcp::wire::{Ipv4Address, Ipv4Cidr, Ipv6Address, Ipv6AddressExt, Ipv6Cidr};

use super::RouteLookupKey;
use crate::{net::iface::Iface, prelude::*};

/// A route that describes how to handle packets for a destination network.
#[derive(Clone)]
pub(super) struct RouteEntry<A: RouteAddressFamily> {
    dst: A::Cidr,
    target: RouteTarget<A>,
    table_id: RouteTableId,
    metric: RouteMetric,
    origin: RouteOrigin<A>,
}

/// What a route does with the packets it matches.
#[derive(Clone)]
enum RouteTarget<A> {
    /// Sends the packets through an interface, to a gateway or directly.
    Iface {
        type_: IfaceRouteType,
        gateway: Option<A>,
        iface: Arc<Iface>,
    },
    /// Refuses the packets without an interface.
    Reject(Rejection),
}

/// The types of the routes that send packets through an interface.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum IfaceRouteType {
    Unicast,
    Local,
    Broadcast,
    Anycast,
    Multicast,
}

/// How a route without an interface refuses the packets it matches.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::net) enum Rejection {
    /// Fails the lookup with `EINVAL`.
    Blackhole,
    /// Fails the lookup with `EHOSTUNREACH`.
    Unreachable,
    /// Fails the lookup with `EACCES`.
    Prohibit,
    /// Ends the lookup in this table, so that the next rule applies.
    Throw,
}

/// A route that a lookup selected to send packets through an interface.
pub(super) struct ResolvedRoute<A> {
    pub(super) type_: RouteType,
    pub(super) gateway: Option<A>,
    pub(super) iface: Arc<Iface>,
    pub(super) table_id: RouteTableId,
}

/// The outcome of a lookup that matched a route.
pub(super) enum RouteMatch<A> {
    Resolved(ResolvedRoute<A>),
    Rejected(Rejection),
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
    /// Creates a route entry that sends packets through an interface.
    ///
    /// Fails if the type is one of a route without an interface.
    pub(super) fn new(
        dst: A::Cidr,
        gateway: Option<A>,
        output_iface: Arc<Iface>,
        table_id: RouteTableId,
        metric: RouteMetric,
        type_: RouteType,
        origin: RouteOrigin<A>,
    ) -> Result<Self> {
        let type_ = match type_ {
            RouteType::Unicast => IfaceRouteType::Unicast,
            RouteType::Local => IfaceRouteType::Local,
            RouteType::Broadcast => IfaceRouteType::Broadcast,
            RouteType::Anycast => IfaceRouteType::Anycast,
            RouteType::Multicast => IfaceRouteType::Multicast,
            RouteType::Blackhole
            | RouteType::Unreachable
            | RouteType::Prohibit
            | RouteType::Throw => {
                return_errno_with_message!(Errno::EINVAL, "the route type has no interface")
            }
        };
        let target = RouteTarget::Iface {
            type_,
            gateway,
            iface: output_iface,
        };
        Self::with_target(dst, target, table_id, metric, origin)
    }

    /// Creates a route entry that refuses packets without an interface.
    pub(super) fn reject(
        dst: A::Cidr,
        rejection: Rejection,
        table_id: RouteTableId,
        metric: RouteMetric,
        origin: RouteOrigin<A>,
    ) -> Result<Self> {
        Self::with_target(dst, RouteTarget::Reject(rejection), table_id, metric, origin)
    }

    fn with_target(
        dst: A::Cidr,
        target: RouteTarget<A>,
        table_id: RouteTableId,
        metric: RouteMetric,
        origin: RouteOrigin<A>,
    ) -> Result<Self> {
        if dst != A::network(&dst) {
            return_errno_with_message!(Errno::EINVAL, "the route destination is not canonical");
        }

        Ok(Self {
            dst,
            target,
            table_id,
            metric,
            origin,
        })
    }

    /// Returns the destination network.
    pub(super) const fn dst(&self) -> &A::Cidr {
        &self.dst
    }

    /// Returns the next-hop gateway.
    pub(super) const fn gateway(&self) -> Option<A> {
        match &self.target {
            RouteTarget::Iface { gateway, .. } => *gateway,
            RouteTarget::Reject(_) => None,
        }
    }

    /// Returns the output interface, which a route that refuses packets does not have.
    pub(super) const fn output_iface(&self) -> Option<&Arc<Iface>> {
        match &self.target {
            RouteTarget::Iface { iface, .. } => Some(iface),
            RouteTarget::Reject(_) => None,
        }
    }

    /// Whether the route sends packets through the interface with the given index.
    pub(super) fn leaves_through(&self, iface_index: u32) -> bool {
        self.output_iface()
            .is_some_and(|iface| iface.index() == iface_index)
    }

    /// Returns what a lookup that selects the route does with a packet.
    pub(super) fn to_match(&self) -> RouteMatch<A> {
        match &self.target {
            RouteTarget::Iface {
                type_,
                gateway,
                iface,
            } => RouteMatch::Resolved(ResolvedRoute {
                type_: (*type_).into(),
                gateway: *gateway,
                iface: iface.clone(),
                table_id: self.table_id,
            }),
            RouteTarget::Reject(rejection) => RouteMatch::Rejected(*rejection),
        }
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
    pub(super) fn type_(&self) -> RouteType {
        match &self.target {
            RouteTarget::Iface { type_, .. } => (*type_).into(),
            RouteTarget::Reject(rejection) => (*rejection).into(),
        }
    }

    /// Returns the origin of the route.
    pub(super) const fn origin(&self) -> &RouteOrigin<A> {
        &self.origin
    }

    /// Whether both entries describe the same route through the same interface.
    pub(super) fn is_same_route(&self, other: &Self) -> bool {
        self.has_same_key(other)
            && self.gateway() == other.gateway()
            && self.type_() == other.type_()
            && self.origin.protocol == other.origin.protocol
            && self.origin.scope == other.origin.scope
            && self.origin.preferred_source == other.origin.preferred_source
    }

    /// Whether both entries occupy the same slot of the same routing table.
    pub(super) fn has_same_key(&self, other: &Self) -> bool {
        self.table_id == other.table_id
            && self.dst == other.dst
            && self.metric == other.metric
            && self.output_iface().map(|iface| iface.index())
                == other.output_iface().map(|iface| iface.index())
    }

    pub(super) fn matches_lookup(&self, key: &RouteLookupKey<A>) -> bool {
        let reaches_device = match &self.target {
            RouteTarget::Iface { iface, .. } => {
                key.device.is_none_or(|device| iface.index() == device)
            }
            RouteTarget::Reject(_) => true,
        };
        A::contains(&self.dst, key.dst())
            && reaches_device
            && (!key.direct
                || self.gateway().is_none() && self.origin.scope.get() >= RouteScope::LINK.get())
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
    /// Delivers packets to the nearest member of an anycast group.
    Anycast = 4,
    /// Delivers IPv4 multicasts.
    Multicast = 5,
    /// Discards packets.
    Blackhole = 6,
    /// Rejects packets as unreachable.
    Unreachable = 7,
    /// Rejects packets as administratively prohibited.
    Prohibit = 8,
    /// Continues the lookup with the next rule.
    Throw = 9,
}

impl From<IfaceRouteType> for RouteType {
    fn from(type_: IfaceRouteType) -> Self {
        match type_ {
            IfaceRouteType::Unicast => Self::Unicast,
            IfaceRouteType::Local => Self::Local,
            IfaceRouteType::Broadcast => Self::Broadcast,
            IfaceRouteType::Anycast => Self::Anycast,
            IfaceRouteType::Multicast => Self::Multicast,
        }
    }
}

impl From<Rejection> for RouteType {
    fn from(rejection: Rejection) -> Self {
        match rejection {
            Rejection::Blackhole => Self::Blackhole,
            Rejection::Unreachable => Self::Unreachable,
            Rejection::Prohibit => Self::Prohibit,
            Rejection::Throw => Self::Throw,
        }
    }
}
