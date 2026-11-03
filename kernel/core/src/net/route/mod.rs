// SPDX-License-Identifier: MPL-2.0

//! Unified IP routing management.
//!
//! This module manages IP route information.
//! Callers can look up the local interface that owns an address when binding a socket,
//! or select an output interface when connecting an unbound socket.

use aster_bigtcp::{
    iface::{InterfaceFlags, InterfaceType},
    wire::{IpAddress, IpEndpoint, Ipv4Address, Ipv4Cidr, Ipv6Address, Ipv6Cidr},
};
use spin::Once;

pub(super) use self::{
    user::{Ipv4RouteSelector, NewIpv4Route},
    dump::{RouteRecord, RuleOutcome, RuleRecord, dump_routes, dump_rules},
    entry::{RouteProtocol, RouteScope, RouteType},
};
use self::{dump::entry_record, manager::RouteManager, rule::Rule};
use super::iface::{
    self, Iface,
    config::{self, InterfaceAddress},
};
use crate::prelude::*;

mod dump;
mod entry;
mod manager;
mod rule;
mod table;
mod user;

use entry::{RouteAddressFamily, RouteEntry, RouteMetric, RouteOrigin, RouteTableId};

static IPV4_ROUTE_MANAGER: Once<RwMutex<RouteManager<Ipv4Address>>> = Once::new();
static IPV6_ROUTE_MANAGER: Once<RwMutex<RouteManager<Ipv6Address>>> = Once::new();

/// A route lookup key for one address family.
#[derive(Clone, Debug)]
struct RouteLookupKey<A: RouteAddressFamily> {
    dst: A,
    direct: bool,
    device: Option<u32>,
    // TODO: Add selectors required by route netlink queries,
    // such as a source address, TOS, packet mark, and input/output interface.
}

impl<A: RouteAddressFamily> RouteLookupKey<A> {
    /// Creates a new route lookup key.
    const fn new(dst: A) -> Self {
        Self { dst, direct: false, device: None }
    }

    const fn direct(dst: A, device: Option<u32>) -> Self {
        Self { dst, direct: true, device }
    }

    const fn dst(&self) -> &A {
        &self.dst
    }
}

pub(super) fn init() {
    const LOCAL_RULE_PRIORITY: u32 = 0;
    const MAIN_RULE_PRIORITY: u32 = 32766;
    const DEFAULT_RULE_PRIORITY: u32 = 32767;

    IPV4_ROUTE_MANAGER.call_once(|| {
        let routes = iface::iter_all_ifaces()
            .flat_map(|iface| iface_ipv4_routes(iface, &config::ipv4_addresses(iface)))
            .collect();
        RwMutex::new(RouteManager::new(
            &[
                Rule::lookup(LOCAL_RULE_PRIORITY, RouteTableId::LOCAL),
                Rule::lookup(MAIN_RULE_PRIORITY, RouteTableId::MAIN),
                Rule::lookup(DEFAULT_RULE_PRIORITY, RouteTableId::DEFAULT),
            ],
            routes,
        ))
    });

    IPV6_ROUTE_MANAGER.call_once(|| {
        let routes = iface::iter_all_ifaces()
            .flat_map(iface_ipv6_routes)
            .collect();
        RwMutex::new(RouteManager::new(
            &[
                Rule::lookup(LOCAL_RULE_PRIORITY, RouteTableId::LOCAL),
                Rule::lookup(MAIN_RULE_PRIORITY, RouteTableId::MAIN),
            ],
            routes,
        ))
    });
}

fn iface_ipv4_routes(
    iface: &Arc<Iface>,
    addresses: &[InterfaceAddress],
) -> Vec<RouteEntry<Ipv4Address>> {
    let mut routes = Vec::new();

    for address in addresses {
        let cidr = address.cidr();
        let primary = addresses
            .iter()
            .find(|candidate| !candidate.is_secondary() && is_on_network_of(candidate, address))
            .unwrap_or(address);
        let preferred_source = primary.address();

        // Add a local-table route for the address itself.
        let entry = RouteEntry::new(
            Ipv4Cidr::new(cidr.address(), 32),
            None,
            iface.clone(),
            RouteTableId::LOCAL,
            RouteMetric::default(),
            RouteType::Local,
            kernel_origin(RouteScope::HOST, preferred_source),
        )
        .unwrap();
        routes.push(entry);

        // Add the broadcast address that user space assigned.
        if let Some(broadcast) = address.broadcast()
            && !broadcast.is_broadcast()
        {
            routes.push(broadcast_route(iface, broadcast, preferred_source));
        }

        // Secondary addresses share the connected network of their primary address.
        let network = cidr.network();
        let has_connected_network = !address.is_secondary()
            && !network.address().is_unspecified()
            && (network.address() != cidr.address() || cidr.prefix_len() < 32);
        if !has_connected_network {
            continue;
        }

        // Add a route for the connected network.
        let (table_id, type_) = if iface.type_() == InterfaceType::LOOPBACK {
            (RouteTableId::LOCAL, RouteType::Local)
        } else {
            (RouteTableId::MAIN, RouteType::Unicast)
        };
        let entry = RouteEntry::new(
            network,
            None,
            iface.clone(),
            table_id,
            RouteMetric::default(),
            type_,
            kernel_origin(
                if type_ == RouteType::Local {
                    RouteScope::HOST
                } else {
                    RouteScope::LINK
                },
                preferred_source,
            ),
        )
        .unwrap();
        routes.push(entry);

        // Add a local-table route for the broadcast address of the connected network.
        if cidr.prefix_len() < 31
            && let Some(broadcast) = cidr.broadcast()
        {
            routes.push(broadcast_route(iface, broadcast, preferred_source));
        }
    }

    retain_routes_valid_while_down(iface, &mut routes);

    routes
}

fn is_on_network_of(candidate: &InterfaceAddress, address: &InterfaceAddress) -> bool {
    candidate.cidr().prefix_len() == address.cidr().prefix_len()
        && candidate.cidr().network() == address.cidr().network()
}

fn broadcast_route(
    iface: &Arc<Iface>,
    broadcast: Ipv4Address,
    preferred_source: Ipv4Address,
) -> RouteEntry<Ipv4Address> {
    RouteEntry::new(
        Ipv4Cidr::new(broadcast, 32),
        None,
        iface.clone(),
        RouteTableId::LOCAL,
        RouteMetric::default(),
        RouteType::Broadcast,
        kernel_origin(RouteScope::LINK, preferred_source),
    )
    .unwrap()
}

/// Keeps only the routes that deliver to the host itself when the interface is down.
fn retain_routes_valid_while_down<A: RouteAddressFamily>(
    iface: &Arc<Iface>,
    routes: &mut Vec<RouteEntry<A>>,
) {
    if !iface.flags().contains(InterfaceFlags::UP) {
        routes.retain(|route| route.origin().scope == RouteScope::HOST);
    }
}

fn kernel_origin<A: RouteAddressFamily>(scope: RouteScope, preferred_source: A) -> RouteOrigin<A> {
    RouteOrigin {
        protocol: RouteProtocol::KERNEL,
        scope,
        preferred_source: Some(preferred_source),
    }
}

fn iface_ipv6_routes(iface: &Arc<Iface>) -> Vec<RouteEntry<Ipv6Address>> {
    let mut routes = Vec::new();

    let Some(iface_cidr) = iface.ipv6_cidr() else {
        return routes;
    };

    // Derive up to two routes from the interface's IPv6 configuration.
    // The first covers its own address.
    // For a non-loopback interface, the second covers its connected network.

    // Add a local-table route for the interface's own address.
    let entry = RouteEntry::new(
        Ipv6Cidr::new(iface_cidr.address(), 128),
        None,
        iface.clone(),
        RouteTableId::LOCAL,
        RouteMetric::default(),
        RouteType::Local,
        RouteOrigin {
            protocol: RouteProtocol::KERNEL,
            scope: RouteScope::UNIVERSE,
            preferred_source: None,
        },
    )
    .unwrap();
    routes.push(entry);
    retain_routes_valid_while_down(iface, &mut routes);

    // TODO: Add a main-table route for the connected network of a non-loopback interface.
    // IPv6 doesn't seem to have a connected network(like `127.0.0.0/8` for IPv4)
    // for the IPv6 loopback address (`::1`), which may need further confirmation.

    // TODO: Import IPv6 routes from the interface's internal routing table
    // once any are configured.

    routes
}

/// How the routes the kernel derives for an interface changed.
pub(in crate::net) struct IfaceRouteChanges {
    pub removed: Vec<RouteRecord>,
    pub added: Vec<RouteRecord>,
}

/// Recomputes the routes of an interface after its link state or addresses changed.
///
/// Bringing an interface down removes the routes through it that leave the host, as Linux does:
/// the connected network, broadcast and gateway routes, and every route that user space
/// installed. The routes that deliver to the host's own addresses stay. Bringing the interface up
/// restores the routes the kernel derives from its addresses. While an interface is down, a new
/// address gains only its own route. Removing the last address of an interface removes every
/// route through it.
pub(super) fn sync_iface_routes(
    iface: &Arc<Iface>,
    addresses: &[InterfaceAddress],
) -> IfaceRouteChanges {
    let up = iface.flags().contains(InterfaceFlags::UP);
    let changes = {
        let mut manager = IPV4_ROUTE_MANAGER.get().unwrap().write();
        let mut derived = iface_ipv4_routes(iface, addresses);
        if !up {
            let existing = manager.derived_routes_of(iface.index());
            derived.retain(|route| {
                is_address_route(route) || existing.iter().any(|entry| entry.is_same_route(route))
            });
        }
        let changes = manager.replace_iface_routes(
            iface.index(),
            up && !addresses.is_empty(),
            derived,
        );
        sync_gateway_routes(&manager, iface)
            .expect("fewer gateway routes fit in the table that held more");
        changes
    };
    IPV6_ROUTE_MANAGER
        .get()
        .unwrap()
        .write()
        .replace_iface_routes(iface.index(), up, iface_ipv6_routes(iface));

    let mut removed: Vec<RouteRecord> = changes.removed.iter().map(entry_record).collect();
    removed.sort_by_key(|record| match record.type_ {
        RouteType::Local if record.destination_prefix_len == 32 => 2,
        RouteType::Broadcast => 1,
        _ => 0,
    });
    IfaceRouteChanges {
        removed,
        added: changes.added.iter().map(entry_record).collect(),
    }
}

/// Whether the route delivers to one address of the host itself.
fn is_address_route(route: &RouteEntry<Ipv4Address>) -> bool {
    route.type_() == RouteType::Local && route.dst().prefix_len() == 32
}

/// Installs a unicast IPv4 route. The caller holds the interface configuration lock.
pub(super) fn add_ipv4_route(
    request: NewIpv4Route,
    addresses: &[InterfaceAddress],
) -> Result<RouteRecord> {
    user::add_ipv4_route(request, addresses)
}

/// Removes an IPv4 route that user space installed. The caller holds the interface configuration
/// lock.
pub(super) fn remove_ipv4_route(selector: &Ipv4RouteSelector) -> Result<RouteRecord> {
    user::remove_ipv4_route(selector)
}

/// Gives an interface the main-table gateway routes through it, for next-hop selection.
fn sync_gateway_routes(manager: &RouteManager<Ipv4Address>, iface: &Arc<Iface>) -> Result<()> {
    let mut routes: Vec<(Ipv4Cidr, Ipv4Address)> = Vec::new();
    for entry in manager.entries() {
        let Some(gateway) = entry.gateway() else {
            continue;
        };
        if entry.table_id() == RouteTableId::MAIN
            && entry.output_iface().index() == iface.index()
            && !routes.iter().any(|(cidr, _)| cidr == entry.dst())
        {
            routes.push((*entry.dst(), gateway));
        }
    }
    iface.set_ipv4_gateway_routes(&routes).map_err(|_| {
        Error::with_message(Errno::ENOBUFS, "the interface cannot hold more gateway routes")
    })
}

/// Looks up the output interface for an IP destination.
pub(super) fn lookup_iface(dst: IpAddress) -> Result<Arc<Iface>> {
    lookup_iface_with_scope(dst, false, None)
}

pub(super) fn lookup_direct_iface(dst: IpAddress, device: Option<u32>) -> Result<Arc<Iface>> {
    lookup_iface_with_scope(dst, true, device)
}

fn lookup_iface_with_scope(dst: IpAddress, direct: bool, device: Option<u32>) -> Result<Arc<Iface>> {
    let iface = match dst {
        IpAddress::Ipv4(dst) => IPV4_ROUTE_MANAGER
            .get()
            .unwrap()
            .read()
            .lookup_entry(&if direct { RouteLookupKey::direct(dst, device) } else { RouteLookupKey::new(dst) })?
            .output_iface()
            .clone(),
        IpAddress::Ipv6(dst) => IPV6_ROUTE_MANAGER
            .get()
            .unwrap()
            .read()
            .lookup_entry(&if direct { RouteLookupKey::direct(dst, device) } else { RouteLookupKey::new(dst) })?
            .output_iface()
            .clone(),
    };
    Ok(iface)
}

/// Looks up the interface that owns a local IP address.
pub(super) fn lookup_local_iface(address: IpAddress) -> Result<Arc<Iface>> {
    let (type_, iface) = match address {
        IpAddress::Ipv4(address) => {
            let entry = IPV4_ROUTE_MANAGER
                .get()
                .unwrap()
                .read()
                .lookup_in_local_table(&RouteLookupKey::new(address))
                .ok_or_else(|| {
                    Error::with_message(
                        Errno::EADDRNOTAVAIL,
                        "the address is not available from the local machine",
                    )
                })?;
            (entry.type_(), entry.output_iface().clone())
        }
        IpAddress::Ipv6(address) => {
            let entry = IPV6_ROUTE_MANAGER
                .get()
                .unwrap()
                .read()
                .lookup_in_local_table(&RouteLookupKey::new(address))
                .ok_or_else(|| {
                    Error::with_message(
                        Errno::EADDRNOTAVAIL,
                        "the address is not available from the local machine",
                    )
                })?;
            (entry.type_(), entry.output_iface().clone())
        }
    };

    // Linux doesn't check the route type when adding a new route to the local table,
    // so we need to verify that the route type is local when an entry is found.
    // Reference: <https://elixir.bootlin.com/linux/v7.1/source/include/net/inet_sock.h#L441-L451>.
    if type_ != RouteType::Local && type_ != RouteType::Broadcast {
        return_errno_with_message!(
            Errno::EADDRNOTAVAIL,
            "the address is not available from the local machine"
        );
    }
    Ok(iface)
}

/// Returns whether an endpoint is an IPv4 broadcast destination.
///
/// IPv6 does not define broadcast addresses,
/// so IPv6 endpoints always return `false`.
pub(super) fn is_broadcast_endpoint(endpoint: &IpEndpoint) -> bool {
    let IpAddress::Ipv4(address) = endpoint.addr else {
        return false;
    };

    address.is_broadcast()
        || IPV4_ROUTE_MANAGER
            .get()
            .unwrap()
            .read()
            .lookup_entry(&RouteLookupKey::new(address))
            .is_ok_and(|entry| entry.type_() == RouteType::Broadcast)
}
