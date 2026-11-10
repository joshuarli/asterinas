// SPDX-License-Identifier: MPL-2.0

//! IPv4 routes that user space installs and removes.

use aster_bigtcp::{
    iface::InterfaceFlags,
    wire::{Ipv4Address, Ipv4Cidr},
};

use super::{
    IPV4_ROUTE_MANAGER, RouteRecord, dump::entry_record, RouteEntry, RouteMetric, RouteOrigin, RouteProtocol, RouteScope,
    RouteTableId, RouteType, entry::Rejection,
};
use crate::{
    net::iface::{Iface, config::InterfaceAddress, iter_all_ifaces},
    prelude::*,
};

/// The scope from which a route can no longer have a gateway (`RT_SCOPE_LINK`).
const FIRST_SCOPE_WITHOUT_GATEWAY: u8 = 253;

/// `RT_SCOPE_NOWHERE`, which a removal request uses for "any scope".
const ANY_SCOPE: u8 = 255;

/// What an installed route does with the packets it matches.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::net) enum NewRouteAction {
    /// Sends the packets through an interface.
    Unicast,
    /// Refuses the packets without an interface.
    Reject(Rejection),
}

/// A request to install a route.
pub(in crate::net) struct NewIpv4Route {
    pub action: NewRouteAction,
    pub table: u32,
    pub destination: Ipv4Cidr,
    pub gateway: Option<Ipv4Address>,
    pub iface_index: Option<u32>,
    pub priority: u32,
    pub protocol: u8,
    pub scope: u8,
}

/// Selects the route a removal request removes.
///
/// Every field that is present must match, as in Linux.
pub(in crate::net) struct Ipv4RouteSelector {
    pub table: u32,
    pub destination: Ipv4Cidr,
    pub priority: Option<u32>,
    pub gateway: Option<Ipv4Address>,
    pub iface_index: Option<u32>,
    pub protocol: Option<u8>,
    pub type_: Option<u8>,
    pub scope: Option<u8>,
}

/// Installs a route. The caller holds the interface configuration lock and passes the addresses
/// of all interfaces.
pub(super) fn add_ipv4_route(
    request: NewIpv4Route,
    addresses: &[InterfaceAddress],
) -> Result<RouteRecord> {
    if request.destination != request.destination.network() {
        return_errno_with_message!(Errno::EINVAL, "the route destination is not a network");
    }

    if let NewRouteAction::Reject(rejection) = request.action {
        return add_reject_route(&request, rejection);
    }

    let iface = route_iface(&request, addresses)?;
    if !iface.flags().contains(InterfaceFlags::UP) {
        return_errno_with_message!(Errno::ENETDOWN, "the route interface is down");
    }

    if let Some(gateway) = request.gateway {
        if request.scope >= FIRST_SCOPE_WITHOUT_GATEWAY {
            return_errno_with_message!(Errno::EINVAL, "a route with a gateway has a narrow scope");
        }
        if !is_on_connected_network(&iface, addresses, gateway) {
            return_errno_with_message!(Errno::ENETUNREACH, "the gateway is not reachable");
        }
    }

    let entry = RouteEntry::new(
        request.destination,
        request.gateway,
        iface.clone(),
        RouteTableId::new(request.table),
        RouteMetric::new(request.priority),
        RouteType::Unicast,
        RouteOrigin {
            protocol: RouteProtocol::new(request.protocol),
            scope: RouteScope::new(request.scope),
            preferred_source: None,
        },
    )?;
    let table_id = entry.table_id();
    let metric = entry.metric();
    let record = entry_record(&entry);

    let mut manager = IPV4_ROUTE_MANAGER.get().unwrap().write();
    manager.insert_user_route(entry)?;
    if let Err(error) = super::sync_gateway_routes(&manager, &iface) {
        manager.remove_route(table_id, &request.destination, metric);
        return Err(error);
    }

    super::publish_ipv4_poll_routes(&manager);
    Ok(record)
}

/// Installs a route that refuses packets, which Linux accepts without a gateway or a device.
fn add_reject_route(request: &NewIpv4Route, rejection: Rejection) -> Result<RouteRecord> {
    if request.gateway.is_some() || request.iface_index.is_some() {
        return_errno_with_message!(
            Errno::EINVAL,
            "a route of this type cannot have a gateway or a device"
        );
    }

    let entry = RouteEntry::reject(
        request.destination,
        rejection,
        RouteTableId::new(request.table),
        RouteMetric::new(request.priority),
        RouteOrigin {
            protocol: RouteProtocol::new(request.protocol),
            scope: RouteScope::new(request.scope),
            preferred_source: None,
        },
    )?;
    let record = entry_record(&entry);

    let mut manager = IPV4_ROUTE_MANAGER.get().unwrap().write();
    manager.insert_user_route(entry)?;
    super::publish_ipv4_poll_routes(&manager);
    Ok(record)
}

/// Removes a route. The caller holds the interface configuration lock.
pub(super) fn remove_ipv4_route(selector: &Ipv4RouteSelector) -> Result<RouteRecord> {
    let mut manager = IPV4_ROUTE_MANAGER.get().unwrap().write();

    let table_id = RouteTableId::new(selector.table);
    let Some(entry) = manager.find_route(table_id, &selector.destination, |entry| {
        selector.priority.is_none_or(|priority| priority == entry.metric().get())
            && selector.gateway.is_none_or(|gateway| Some(gateway) == entry.gateway())
            && selector
                .iface_index
                .is_none_or(|index| entry.leaves_through(index))
            && selector
                .protocol
                .is_none_or(|protocol| protocol == entry.origin().protocol.get())
            && selector.type_.is_none_or(|type_| type_ == entry.type_() as u8)
            && selector
                .scope
                .is_none_or(|scope| scope == ANY_SCOPE || scope == entry.origin().scope.get())
    }) else {
        return_errno_with_message!(Errno::ESRCH, "no such route");
    };

    if entry.origin().protocol == RouteProtocol::KERNEL {
        return_errno_with_message!(
            Errno::EOPNOTSUPP,
            "a route that the kernel derives from an address cannot be removed"
        );
    }

    manager.remove_route(table_id, &selector.destination, entry.metric());
    if let Some(iface) = entry.output_iface() {
        super::sync_gateway_routes(&manager, iface)
            .expect("fewer gateway routes fit in the table that held more");
    }
    super::publish_ipv4_poll_routes(&manager);

    Ok(entry_record(&entry))
}

fn route_iface(request: &NewIpv4Route, addresses: &[InterfaceAddress]) -> Result<Arc<Iface>> {
    if let Some(index) = request.iface_index {
        return iter_all_ifaces()
            .find(|iface| iface.index() == index)
            .cloned()
            .ok_or_else(|| {
                // Linux resolves a gateway through the interface, which fails as unreachable.
                let errno = if request.gateway.is_some() {
                    Errno::ENETUNREACH
                } else {
                    Errno::ENODEV
                };
                Error::with_message(errno, "no interface found")
            });
    }

    let Some(gateway) = request.gateway else {
        return_errno_with_message!(Errno::EINVAL, "a route needs an interface or a gateway");
    };
    addresses
        .iter()
        .find(|address| {
            address.iface().flags().contains(InterfaceFlags::UP)
                && address.cidr().contains_addr(&gateway)
        })
        .map(|address| address.iface().clone())
        .ok_or_else(|| Error::with_message(Errno::ENETUNREACH, "the gateway is not reachable"))
}

fn is_on_connected_network(
    iface: &Arc<Iface>,
    addresses: &[InterfaceAddress],
    gateway: Ipv4Address,
) -> bool {
    addresses
        .iter()
        .filter(|address| Arc::ptr_eq(address.iface(), iface))
        .any(|address| address.cidr().contains_addr(&gateway))
}
