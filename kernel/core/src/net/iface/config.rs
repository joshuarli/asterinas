// SPDX-License-Identifier: MPL-2.0

//! The configuration of interfaces that user space changes: link state and IPv4 addresses.
//!
//! One lock serializes every change together with the update of the interface and the routes
//! derived from it, so the routes always reflect the latest configuration.

use aster_bigtcp::{
    iface::{InterfaceFlags, InterfaceName},
    wire::{Ipv4Address, Ipv4Cidr},
};
use spin::Once;

use super::{Iface, iter_all_ifaces};
use crate::{
    net::{
        route::{self, IfaceRouteChanges, Ipv4RouteSelector, Ipv4RuleRequest, NewIpv4Route},
        socket::netlink::{NetworkEvent, RequestOrigin, publish_network_events},
    },
    prelude::*,
};

/// The state of the lock is the list of all IPv4 addresses.
///
/// Addresses of one interface keep Linux's order: primary addresses in the order they were added,
/// then secondary addresses.
static IPV4_ADDRESSES: Once<Mutex<Vec<InterfaceAddress>>> = Once::new();

/// An IPv4 address assigned to an interface.
#[derive(Clone)]
pub(in crate::net) struct InterfaceAddress {
    iface: Arc<Iface>,
    cidr: Ipv4Cidr,
    broadcast: Option<Ipv4Address>,
    label: InterfaceName,
    scope: u8,
    secondary: bool,
    created_centiseconds: u32,
}

impl InterfaceAddress {
    pub(in crate::net) fn iface(&self) -> &Arc<Iface> {
        &self.iface
    }

    /// The address together with the prefix length of its network.
    pub(in crate::net) fn cidr(&self) -> Ipv4Cidr {
        self.cidr
    }

    pub(in crate::net) fn address(&self) -> Ipv4Address {
        self.cidr.address()
    }

    /// The broadcast address that user space assigned, if any.
    pub(in crate::net) fn broadcast(&self) -> Option<Ipv4Address> {
        self.broadcast
    }

    pub(in crate::net) fn label(&self) -> &InterfaceName {
        &self.label
    }

    /// The route scope of the address (`rt_scope_t`).
    pub(in crate::net) fn scope(&self) -> u8 {
        self.scope
    }

    /// Whether another address of the same network and prefix length is the primary one.
    pub(in crate::net) fn is_secondary(&self) -> bool {
        self.secondary
    }

    /// The creation time, in hundredths of a second since boot.
    pub(in crate::net) fn created_centiseconds(&self) -> u32 {
        self.created_centiseconds
    }
}

/// A request to assign an IPv4 address.
pub(in crate::net) struct NewAddress {
    pub cidr: Ipv4Cidr,
    pub broadcast: Option<Ipv4Address>,
    pub label: Option<InterfaceName>,
    pub scope: u8,
}

/// Selects the address an unassign request removes.
///
/// Every field that is present must match, as in Linux. A selector with no field matches the
/// first address of the interface.
pub(in crate::net) struct AddressSelector {
    pub local: Option<Ipv4Address>,
    /// An address on the network of the removed address and the prefix length of that network.
    pub network_member: Option<(Ipv4Address, u8)>,
    pub label: Option<InterfaceName>,
}

impl AddressSelector {
    fn matches(&self, address: &InterfaceAddress) -> bool {
        self.local.is_none_or(|local| local == address.address())
            && self.label.is_none_or(|label| label == address.label)
            && self.network_member.is_none_or(|(member, prefix_len)| {
                prefix_len == address.cidr.prefix_len() && address.cidr.contains_addr(&member)
            })
    }
}

pub(super) fn init() {
    let addresses = iter_all_ifaces()
        .filter_map(|iface| {
            let cidr = iface.ipv4_cidr()?;
            Some(InterfaceAddress {
                iface: iface.clone(),
                cidr,
                broadcast: None,
                label: *iface.name(),
                scope: LOOPBACK_SCOPE,
                secondary: false,
                created_centiseconds: 0,
            })
        })
        .collect();
    IPV4_ADDRESSES.call_once(|| Mutex::new(addresses));
}

/// `RT_SCOPE_HOST`, the scope of the loopback address.
const LOOPBACK_SCOPE: u8 = 254;

/// The IPv4 addresses of one interface in Linux's order.
pub(in crate::net) fn ipv4_addresses(iface: &Arc<Iface>) -> Vec<InterfaceAddress> {
    IPV4_ADDRESSES
        .get()
        .unwrap()
        .lock()
        .iter()
        .filter(|address| Arc::ptr_eq(&address.iface, iface))
        .cloned()
        .collect()
}

/// The primary IPv4 address of an interface that a connection from it uses as its source.
pub(in crate::net) fn primary_ipv4_address(iface: &Arc<Iface>) -> Option<Ipv4Address> {
    ipv4_addresses(iface).first().map(InterfaceAddress::address)
}

/// Brings an interface up or down and updates its routes.
///
/// Like Linux, a change reports the link, and bringing an interface up reports the routes that
/// return. Taking an interface down flushes its routes without reporting them.
pub(in crate::net) fn set_administratively_up(iface: &Arc<Iface>, up: bool) {
    let addresses = IPV4_ADDRESSES.get().unwrap().lock();
    let was_up = iface.flags().contains(InterfaceFlags::UP);
    iface.set_administratively_up(up);
    let changes = sync(iface, &addresses);
    if was_up == up {
        return;
    }

    let mut events = vec![NetworkEvent::LinkChanged {
        iface: iface.clone(),
        changed_flags: InterfaceFlags::UP,
    }];
    if up {
        events.extend(route_added_events(changes.added));
    }
    publish_network_events(events);
}

pub(in crate::net) fn add_ipv4_rule(request: Ipv4RuleRequest, exclusive: bool, origin: RequestOrigin) -> Result<()> {
    let _addresses = IPV4_ADDRESSES.get().unwrap().lock();
    let rule = route::add_ipv4_rule(request, exclusive)?;
    publish_network_events(vec![NetworkEvent::RuleAdded { rule, origin }]);
    Ok(())
}

pub(in crate::net) fn remove_ipv4_rule(request: Ipv4RuleRequest, origin: RequestOrigin) -> Result<()> {
    let _addresses = IPV4_ADDRESSES.get().unwrap().lock();
    let rule = route::remove_ipv4_rule(request)?;
    publish_network_events(vec![NetworkEvent::RuleRemoved { rule, origin }]);
    Ok(())
}

/// Installs a unicast IPv4 route through an interface.
pub(in crate::net) fn add_ipv4_route(request: NewIpv4Route, origin: RequestOrigin) -> Result<()> {
    let addresses = IPV4_ADDRESSES.get().unwrap().lock();
    let route = route::add_ipv4_route(request, &addresses)?;
    publish_network_events(vec![NetworkEvent::RouteAdded { route, origin }]);
    Ok(())
}

/// Removes an IPv4 route that user space installed.
pub(in crate::net) fn remove_ipv4_route(
    selector: &Ipv4RouteSelector,
    origin: RequestOrigin,
) -> Result<()> {
    let _addresses = IPV4_ADDRESSES.get().unwrap().lock();
    let route = route::remove_ipv4_route(selector)?;
    publish_network_events(vec![NetworkEvent::RouteRemoved { route, origin }]);
    Ok(())
}

/// Assigns an IPv4 address to an interface.
///
/// Like Linux, an address on the network of an existing address with the same prefix length
/// becomes secondary, and assigning an address that the interface already has fails.
pub(in crate::net) fn add_ipv4_address(
    iface: &Arc<Iface>,
    request: NewAddress,
    origin: RequestOrigin,
) -> Result<()> {
    let mut addresses = IPV4_ADDRESSES.get().unwrap().lock();

    let mut secondary = false;
    for address in addresses
        .iter()
        .filter(|address| Arc::ptr_eq(&address.iface, iface))
        .filter(|address| same_network(&address.cidr, &request.cidr))
    {
        if address.address() == request.cidr.address() {
            return_errno_with_message!(Errno::EEXIST, "the interface already has the address");
        }
        if address.scope != request.scope {
            return_errno_with_message!(
                Errno::EINVAL,
                "an address on the same network has another scope"
            );
        }
        secondary = true;
    }
    let new_address = InterfaceAddress {
        iface: iface.clone(),
        cidr: request.cidr,
        broadcast: request.broadcast,
        label: request.label.unwrap_or(*iface.name()),
        scope: request.scope,
        secondary,
        created_centiseconds: now_centiseconds(),
    };

    let mut updated = addresses.clone();
    let position = if secondary {
        updated.len()
    } else {
        // A primary address goes after the last primary address of its interface whose scope is
        // not narrower, and before every secondary address.
        let last_primary = updated
            .iter()
            .rposition(|address| {
                Arc::ptr_eq(&address.iface, iface)
                    && !address.secondary
                    && new_address.scope <= address.scope
            })
            .map(|index| index + 1);
        let first_of_iface = updated
            .iter()
            .position(|address| Arc::ptr_eq(&address.iface, iface));
        last_primary.or(first_of_iface).unwrap_or(updated.len())
    };
    updated.insert(position, new_address.clone());

    let changes = commit(iface, &mut addresses, updated)?;
    let mut events = vec![NetworkEvent::AddressAdded {
        address: new_address,
        origin,
    }];
    events.extend(route_added_events(changes.added));
    publish_network_events(events);
    Ok(())
}

/// Removes an IPv4 address and the secondary addresses that depend on it.
///
/// Like Linux, the dependent secondary addresses go first, each reported together with its routes,
/// and the address itself goes last.
pub(in crate::net) fn remove_ipv4_address(
    iface: &Arc<Iface>,
    selector: &AddressSelector,
    origin: RequestOrigin,
) -> Result<()> {
    let mut addresses = IPV4_ADDRESSES.get().unwrap().lock();

    let Some(removed) = addresses
        .iter()
        .find(|address| Arc::ptr_eq(&address.iface, iface) && selector.matches(address))
    else {
        return_errno_with_message!(
            Errno::EADDRNOTAVAIL,
            "the interface does not have the address"
        );
    };
    let removed = removed.clone();

    let mut removals: Vec<InterfaceAddress> = Vec::new();
    if !removed.secondary {
        removals.extend(
            addresses
                .iter()
                .filter(|address| {
                    Arc::ptr_eq(&address.iface, iface)
                        && address.secondary
                        && same_network(&address.cidr, &removed.cidr)
                })
                .cloned(),
        );
    }
    removals.push(removed);

    let mut events = Vec::new();
    for removal in removals {
        let updated = addresses
            .iter()
            .filter(|address| {
                !(Arc::ptr_eq(&address.iface, iface) && address.address() == removal.address())
            })
            .cloned()
            .collect();
        let changes = commit(iface, &mut addresses, updated)?;
        events.push(NetworkEvent::AddressRemoved {
            address: removal,
            origin,
        });
        events.extend(changes.removed.into_iter().map(|route| NetworkEvent::RouteRemoved {
            route,
            origin: RequestOrigin::KERNEL,
        }));
    }
    publish_network_events(events);
    Ok(())
}

fn route_added_events(routes: Vec<route::RouteRecord>) -> impl Iterator<Item = NetworkEvent> {
    routes.into_iter().map(|route| NetworkEvent::RouteAdded {
        route,
        origin: RequestOrigin::KERNEL,
    })
}

fn commit(
    iface: &Arc<Iface>,
    addresses: &mut Vec<InterfaceAddress>,
    updated: Vec<InterfaceAddress>,
) -> Result<IfaceRouteChanges> {
    let cidrs: Vec<Ipv4Cidr> = updated
        .iter()
        .filter(|address| Arc::ptr_eq(&address.iface, iface))
        .map(InterfaceAddress::cidr)
        .collect();
    iface.set_ipv4_cidrs(&cidrs).map_err(|_| {
        Error::with_message(Errno::ENOBUFS, "the interface cannot hold more addresses")
    })?;

    *addresses = updated;
    Ok(sync(iface, addresses))
}

fn sync(iface: &Arc<Iface>, addresses: &[InterfaceAddress]) -> IfaceRouteChanges {
    let own: Vec<InterfaceAddress> = addresses
        .iter()
        .filter(|address| Arc::ptr_eq(&address.iface, iface))
        .cloned()
        .collect();
    route::sync_iface_routes(iface, &own)
}

fn same_network(first: &Ipv4Cidr, second: &Ipv4Cidr) -> bool {
    first.prefix_len() == second.prefix_len() && first.network() == second.network()
}

fn now_centiseconds() -> u32 {
    (aster_time::read_monotonic_time().as_millis() / 10) as u32
}
