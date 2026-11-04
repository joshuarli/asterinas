// SPDX-License-Identifier: MPL-2.0

use alloc::{collections::{btree_set::BTreeSet, VecDeque}, sync::Arc, vec::Vec};
use core::{
    borrow::Borrow,
    sync::atomic::{AtomicU64, Ordering},
};

use smoltcp::iface::Route;

use crate::{
    errors::{AddressTableFull, RouteTableFull},
    ext::Ext,
    socket::{NeedIfacePoll, TcpConnectionBg},
};

use super::{common::TxPacketWithDst, wire::ip::Ipv4Reassembly};
use crate::packet::{NetworkLayer, RxPacket};

fn is_unicast_local_v4(addresses: &[smoltcp::wire::Ipv4Cidr], destination: smoltcp::wire::Ipv4Address) -> bool {
    addresses.iter().any(|cidr| {
        let address = cidr.address();
        address == destination || address.is_loopback() && destination.is_loopback()
    })
}

/// An interface with auxiliary data that makes it pollable.
///
/// This is used, for example, when updating a socket's next poll time and finding a socket to
/// poll.
pub(crate) struct PollableIface<E: Ext> {
    interface: smoltcp::iface::Interface,
    pending_conns: PendingConnSet<E>,
    pending_fragments: VecDeque<TxPacketWithDst>,
    reassembly: Ipv4Reassembly,
    /// The IPv4 addresses of the interface, primary first.
    ///
    /// `smoltcp` keeps its own copy, but exposes only the first IPv4 address while it is
    /// borrowed for polling.
    ipv4_cidrs: Vec<smoltcp::wire::Ipv4Cidr>,
}

impl<E: Ext> PollableIface<E> {
    pub(super) fn new(interface: smoltcp::iface::Interface) -> Self {
        let ipv4_cidrs = interface
            .ip_addrs()
            .iter()
            .filter_map(|cidr| match cidr {
                smoltcp::wire::IpCidr::Ipv4(ipv4_cidr) => Some(*ipv4_cidr),
                smoltcp::wire::IpCidr::Ipv6(_) => None,
            })
            .collect();
        Self {
            interface,
            pending_conns: PendingConnSet::new(),
            pending_fragments: VecDeque::new(),
            reassembly: Ipv4Reassembly::new(),
            ipv4_cidrs,
        }
    }

    pub(super) fn as_mut(&mut self) -> PollableIfaceMut<'_, E> {
        PollableIfaceMut {
            context: self.interface.context(),
            pending_conns: &mut self.pending_conns,
            pending_fragments: &mut self.pending_fragments,
            reassembly: &mut self.reassembly,
            ipv4_cidrs: &self.ipv4_cidrs,
        }
    }

    pub(super) fn ipv4_cidr(&self) -> Option<smoltcp::wire::Ipv4Cidr> {
        self.interface.ip_addrs().iter().find_map(|cidr| {
            if let smoltcp::wire::IpCidr::Ipv4(ipv4_cidr) = cidr {
                Some(*ipv4_cidr)
            } else {
                None
            }
        })
    }

    pub(super) fn ipv4_cidrs(&self) -> Vec<smoltcp::wire::Ipv4Cidr> {
        self.ipv4_cidrs.clone()
    }

    /// Replaces all IPv4 addresses of the interface and keeps its IPv6 addresses.
    pub(super) fn set_ipv4_cidrs(
        &mut self,
        cidrs: &[smoltcp::wire::Ipv4Cidr],
    ) -> Result<(), AddressTableFull> {
        let ipv6_count = self.interface.ip_addrs().len() - self.ipv4_cidrs.len();
        if ipv6_count + cidrs.len() > smoltcp::config::IFACE_MAX_ADDR_COUNT {
            return Err(AddressTableFull);
        }
        self.interface.update_ip_addrs(|ip_addrs| {
            ip_addrs.retain(|cidr| !matches!(cidr, smoltcp::wire::IpCidr::Ipv4(_)));
            for cidr in cidrs {
                ip_addrs
                    .push(smoltcp::wire::IpCidr::Ipv4(*cidr))
                    .expect("the address table capacity was checked");
            }
        });
        self.ipv4_cidrs = cidrs.to_vec();
        Ok(())
    }

    /// Replaces the IPv4 gateway routes of the interface and keeps its other routes.
    pub(super) fn set_ipv4_gateway_routes(
        &mut self,
        routes: &[(smoltcp::wire::Ipv4Cidr, smoltcp::wire::Ipv4Address)],
    ) -> Result<(), RouteTableFull> {
        let mut result = Ok(());
        self.interface.routes_mut().update(|storage| {
            let kept = storage
                .iter()
                .filter(|route| !matches!(route.cidr, smoltcp::wire::IpCidr::Ipv4(_)))
                .count();
            if kept + routes.len() > smoltcp::config::IFACE_MAX_ROUTE_COUNT {
                result = Err(RouteTableFull);
                return;
            }
            storage.retain(|route| !matches!(route.cidr, smoltcp::wire::IpCidr::Ipv4(_)));
            for (cidr, gateway) in routes {
                storage
                    .push(Route {
                        cidr: smoltcp::wire::IpCidr::Ipv4(*cidr),
                        via_router: smoltcp::wire::IpAddress::Ipv4(*gateway),
                        preferred_until: None,
                        expires_at: None,
                    })
                    .expect("the route table capacity was checked");
            }
        });
        result
    }

    pub(super) fn ipv6_cidr(&self) -> Option<smoltcp::wire::Ipv6Cidr> {
        self.interface.ip_addrs().iter().find_map(|cidr| {
            if let smoltcp::wire::IpCidr::Ipv6(ipv6_cidr) = cidr {
                Some(*ipv6_cidr)
            } else {
                None
            }
        })
    }

    pub(super) fn routes(&mut self) -> Vec<Route> {
        let mut routes = Vec::new();
        self.interface.routes_mut().update(|route_entries| {
            routes.extend(route_entries.iter().copied());
        });
        routes
    }

    /// Returns the next poll time.
    pub(super) fn next_poll_at_ms(&self) -> Option<u64> {
        self.pending_conns.next_poll_at_ms()
    }
}

impl<E: Ext> PollableIface<E> {
    /// Returns the `smoltcp` context for passing to the `smoltcp` APIs.
    pub(crate) fn context_mut(&mut self) -> &mut smoltcp::iface::Context {
        self.interface.context()
    }

    /// Updates the next poll time of `socket` to `poll_at`.
    ///
    /// This method (or [`PollableIfaceMut::update_next_poll_at_ms`]) should be called after network or
    /// user events that change the poll time occur.
    pub(crate) fn update_next_poll_at_ms(
        &mut self,
        socket: &Arc<TcpConnectionBg<E>>,
        poll_at: smoltcp::socket::PollAt,
    ) -> NeedIfacePoll {
        self.pending_conns.update_next_poll_at_ms(socket, poll_at)
    }

    /// Maps an address to the local unicast address if it is a broadcast address.
    ///
    /// For example, if the interface is configured with the address `10.0.2.15/24`, this method
    ///  - will return `10.0.2.15` for `10.0.2.255`, and
    ///  - will return the original address for `10.0.2.15` and `10.0.2.16`.
    ///
    /// Note: "local" means that the IP address belongs to the local interface, not to be confused
    /// with the localhost IP (`127.0.0.1`).
    pub(crate) fn map_broadcast_to_local(
        &self,
        addr: smoltcp::wire::IpAddress,
    ) -> smoltcp::wire::IpAddress {
        use smoltcp::wire::IpAddress;

        if let IpAddress::Ipv4(addr_v4) = addr
            && let Some(cidr_v4) = self
                .ipv4_cidrs
                .iter()
                .find(|cidr| cidr.broadcast() == Some(addr_v4))
        {
            return IpAddress::Ipv4(cidr_v4.address());
        }

        addr
    }
}

/// A mutable reference to a [`PollableIface`].
///
/// This type is reconstructed from mutable references to fields in [`PollableIface`], since the fields
/// must be broken into individual fields during interface polling due to limitations of the
/// [`smoltcp`] APIs.
pub(crate) struct PollableIfaceMut<'a, E: Ext> {
    context: &'a mut smoltcp::iface::Context,
    pending_conns: &'a mut PendingConnSet<E>,
    pending_fragments: &'a mut VecDeque<TxPacketWithDst>,
    reassembly: &'a mut Ipv4Reassembly,
    ipv4_cidrs: &'a [smoltcp::wire::Ipv4Cidr],
}

// FIXME: We provide `new()` and `inner_mut()` as `pub(crate)` methods because it's necessary to
// allow the Rust compiler to check the lifetime for separate fields. We should find better ways to
// avoid these `pub(crate)` methods in the future.
impl<'a, E: Ext> PollableIfaceMut<'a, E> {
    pub(crate) fn new(
        context: &'a mut smoltcp::iface::Context,
        pending_conns: &'a mut PendingConnSet<E>,
        pending_fragments: &'a mut VecDeque<TxPacketWithDst>,
        reassembly: &'a mut Ipv4Reassembly,
        ipv4_cidrs: &'a [smoltcp::wire::Ipv4Cidr],
    ) -> Self {
        Self {
            context,
            pending_conns,
            pending_fragments,
            reassembly,
            ipv4_cidrs,
        }
    }

    pub(crate) fn inner_mut(
        &mut self,
    ) -> (
        &mut smoltcp::iface::Context,
        &mut PendingConnSet<E>,
        &mut VecDeque<TxPacketWithDst>,
        &mut Ipv4Reassembly,
        &'a [smoltcp::wire::Ipv4Cidr],
    ) {
        (self.context, self.pending_conns, self.pending_fragments, self.reassembly, self.ipv4_cidrs)
    }

    /// Returns the IPv4 addresses of the interface, primary first.
    pub(crate) fn ipv4_cidrs(&self) -> &'a [smoltcp::wire::Ipv4Cidr] {
        self.ipv4_cidrs
    }

    pub(super) fn pending_fragments(&mut self) -> &mut VecDeque<TxPacketWithDst> {
        self.pending_fragments
    }

    pub(super) fn reassemble(
        &mut self,
        packet: RxPacket<NetworkLayer>,
        now: i64,
        verify_checksum: bool,
    ) -> Option<RxPacket<NetworkLayer>> {
        let context = &self.context;
        let addresses = self.ipv4_cidrs;
        self.reassembly.receive(packet, now, verify_checksum, |destination| {
            context.is_broadcast(&smoltcp::wire::IpAddress::Ipv4(destination))
                || is_unicast_local_v4(addresses, destination)
        })
    }
}

impl<E: Ext> PollableIfaceMut<'_, E> {
    pub(super) fn pop_pending_tcp(&mut self) -> Option<Arc<TcpConnectionBg<E>>> {
        let now = self.context.now.total_millis() as u64;
        self.pending_conns.pop_tcp_before_now(now)
    }
}

impl<E: Ext> PollableIfaceMut<'_, E> {
    /// Returns whether `dst_addr` is an address of this interface.
    ///
    /// Note: "local" means that the IP address belongs to the local interface, not to be confused
    /// with the localhost IP (`127.0.0.1`).
    pub(crate) fn is_unicast_local(&self, dst_addr: smoltcp::wire::IpAddress) -> bool {
        use smoltcp::wire::IpAddress;

        match dst_addr {
            IpAddress::Ipv4(dst_addr) => is_unicast_local_v4(self.ipv4_cidrs, dst_addr),
            IpAddress::Ipv6(dst_addr) => self.context.ipv6_addr().is_some_and(|addr| addr == dst_addr),
        }
    }

    /// Returns an immutable reference to the `smoltcp` context.
    pub(crate) fn context(&self) -> &smoltcp::iface::Context {
        self.context
    }

    /// Returns the `smoltcp` context for passing to the `smoltcp` APIs.
    pub(crate) fn context_mut(&mut self) -> &mut smoltcp::iface::Context {
        self.context
    }

    /// Updates the next poll time of `socket` to `poll_at`.
    ///
    /// This method (or [`PollableIface::update_next_poll_at_ms`]) should be called after network
    /// or user events that change the poll time occur.
    pub(crate) fn update_next_poll_at_ms(
        &mut self,
        socket: &Arc<TcpConnectionBg<E>>,
        poll_at: smoltcp::socket::PollAt,
    ) -> NeedIfacePoll {
        self.pending_conns.update_next_poll_at_ms(socket, poll_at)
    }
}

/// A key to sort sockets by their next poll time.
pub(crate) struct PollKey {
    next_poll_at_ms: AtomicU64,
    id: usize,
}

impl PartialEq for PollKey {
    fn eq(&self, other: &Self) -> bool {
        self.next_poll_at_ms.load(Ordering::Relaxed)
            == other.next_poll_at_ms.load(Ordering::Relaxed)
            && self.id == other.id
    }
}
impl Eq for PollKey {}
impl PartialOrd for PollKey {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for PollKey {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.next_poll_at_ms
            .load(Ordering::Relaxed)
            .cmp(&other.next_poll_at_ms.load(Ordering::Relaxed))
            .then_with(|| self.id.cmp(&other.id))
    }
}

impl PollKey {
    /// A value indicating that an immediate poll is required.
    const IMMEDIATE_VAL: u64 = 0;
    /// A value indicating that no poll is required.
    const INACTIVE_VAL: u64 = u64::MAX;

    /// Creates a new [`PollKey`].
    ///
    /// `id` must be a unique identifier for the associated socket, as it will be used to locate
    /// the socket to update its next poll time. This is usually done using the address of the
    /// [`Arc`] socket (see [`Arc::as_ptr`]).
    ///
    /// [`Arc`]: alloc::sync::Arc
    /// [`Arc::as_ptr`]: alloc::sync::Arc::as_ptr
    pub(crate) fn new(id: usize) -> Self {
        Self {
            next_poll_at_ms: AtomicU64::new(Self::INACTIVE_VAL),
            id,
        }
    }

    /// Returns whether the next poll is active.
    ///
    /// The next poll is active if there are packets to send or a timer is set, in which case the
    /// socket will live in the pending queue.
    pub(crate) fn is_active(&self) -> bool {
        self.next_poll_at_ms.load(Ordering::Relaxed) != Self::INACTIVE_VAL
    }
}

/// Sockets to poll in the future, sorted by poll time.
pub(crate) struct PendingConnSet<E: Ext>(BTreeSet<PendingTcpConn<E>>);

/// A TCP socket to poll in the future.
///
/// Note that currently only TCP sockets can set a timer to fire in the future, so a
/// [`PendingConnSet`] contains only [`PendingTcpConn`]s.
struct PendingTcpConn<E: Ext>(Arc<TcpConnectionBg<E>>);

impl<E: Ext> PartialEq for PendingTcpConn<E> {
    fn eq(&self, other: &Self) -> bool {
        self.0.poll_key() == other.0.poll_key()
    }
}
impl<E: Ext> Eq for PendingTcpConn<E> {}
impl<E: Ext> PartialOrd for PendingTcpConn<E> {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}
impl<E: Ext> Ord for PendingTcpConn<E> {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.0.poll_key().cmp(other.0.poll_key())
    }
}

impl<E: Ext> Borrow<PollKey> for PendingTcpConn<E> {
    fn borrow(&self) -> &PollKey {
        self.0.poll_key()
    }
}

impl<E: Ext> PendingConnSet<E> {
    fn new() -> Self {
        Self(BTreeSet::new())
    }

    fn update_next_poll_at_ms(
        &mut self,
        socket: &Arc<TcpConnectionBg<E>>,
        poll_at: smoltcp::socket::PollAt,
    ) -> NeedIfacePoll {
        let key = socket.poll_key();
        let old_poll_at_ms = key.next_poll_at_ms.load(Ordering::Relaxed);

        let new_poll_at_ms = match poll_at {
            smoltcp::socket::PollAt::Now => PollKey::IMMEDIATE_VAL,
            smoltcp::socket::PollAt::Time(instant) => instant.total_millis() as u64,
            smoltcp::socket::PollAt::Ingress => PollKey::INACTIVE_VAL,
        };

        // Fast path: There is nothing to update.
        if old_poll_at_ms == new_poll_at_ms {
            return NeedIfacePoll::FALSE;
        }

        // Remove the socket from the pending queue if it is in the queue.
        let owned_socket = if old_poll_at_ms != PollKey::INACTIVE_VAL {
            self.0.take(key).unwrap()
        } else {
            PendingTcpConn(socket.clone())
        };

        // Update the poll time _after_ it is removed from the queue.
        key.next_poll_at_ms.store(new_poll_at_ms, Ordering::Relaxed);

        // If no new poll is required, do not add the socket to the pending queue.
        if new_poll_at_ms == PollKey::INACTIVE_VAL {
            return NeedIfacePoll::FALSE;
        }

        // Add the socket back to the queue.
        let inserted = self.0.insert(owned_socket);
        debug_assert!(inserted);

        if new_poll_at_ms < old_poll_at_ms {
            NeedIfacePoll::TRUE
        } else {
            NeedIfacePoll::FALSE
        }
    }

    fn pop_tcp_before_now(&mut self, now_at_ms: u64) -> Option<Arc<TcpConnectionBg<E>>> {
        if self.0.first().is_some_and(|first| {
            first.0.poll_key().next_poll_at_ms.load(Ordering::Relaxed) <= now_at_ms
        }) {
            self.0.pop_first().map(|first| {
                // Reset `next_poll_at_ms` since the socket is no longer in the queue.
                first
                    .0
                    .poll_key()
                    .next_poll_at_ms
                    .store(PollKey::INACTIVE_VAL, Ordering::Relaxed);
                first.0
            })
        } else {
            None
        }
    }

    fn next_poll_at_ms(&self) -> Option<u64> {
        self.0
            .first()
            .map(|first| first.0.poll_key().next_poll_at_ms.load(Ordering::Relaxed))
    }
}

/// An extension trait for an interface context.
pub(super) trait IsUnicast {
    /// Returns whether the destination address is a unicast address of an interface.
    ///
    /// For example, if the interface is configured with the address `10.0.2.15/24`, this method
    ///  - will return true for `10.0.2.15` and `10.0.2.254`, and
    ///  - will return false for `10.0.2.255` and `255.255.255.255`.
    ///
    /// Note: This excludes broadcast addresses, link-local broadcast addresses, and multicast
    /// addresses.
    fn is_unicast(&self, dst_addr: smoltcp::wire::IpAddress) -> bool;
}

impl IsUnicast for smoltcp::iface::Context {
    fn is_unicast(&self, dst_addr: smoltcp::wire::IpAddress) -> bool {
        !self.is_broadcast(&dst_addr) && !dst_addr.is_multicast()
    }
}
