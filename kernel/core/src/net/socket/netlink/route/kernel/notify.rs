// SPDX-License-Identifier: MPL-2.0

//! Notifications that route netlink delivers to the link, IPv4 address and IPv4 route groups.

use aster_bigtcp::iface::InterfaceFlags;

use super::{
    addr::ipv4_to_addr,
    link::iface_to_new_link,
    route::record_to_route,
};
use crate::{
    net::{
        iface::{Iface, config::InterfaceAddress},
        route::RouteRecord,
        socket::netlink::{
            GroupIdSet,
            message::{CMsgSegHdr, CSegmentType, NewRequestFlags},
            route::message::{RtnlMessage, RtnlSegment},
            table::{NetlinkRouteProtocol, SupportedNetlinkProtocol},
        },
    },
    prelude::*,
};

/// The group of link notifications (`RTMGRP_LINK`).
const LINK_GROUP: u32 = 0x1;
/// The group of IPv4 address notifications (`RTMGRP_IPV4_IFADDR`).
const IPV4_ADDRESS_GROUP: u32 = 0x10;
/// The group of IPv4 route notifications (`RTMGRP_IPV4_ROUTE`).
const IPV4_ROUTE_GROUP: u32 = 0x40;

/// The request that caused a change, whose sequence number and port a notification about an
/// address or a user route echoes. A change that no request caused has neither.
#[derive(Clone, Copy)]
pub(in crate::net) struct RequestOrigin {
    seq: u32,
    pid: u32,
}

impl RequestOrigin {
    pub(in crate::net) const KERNEL: Self = Self { seq: 0, pid: 0 };

    pub(in crate::net) const fn request(header: &CMsgSegHdr) -> Self {
        Self {
            seq: header.seq,
            pid: header.pid,
        }
    }
}

/// A change of network state that user space can subscribe to.
pub(in crate::net) enum NetworkEvent {
    LinkChanged {
        iface: Arc<Iface>,
        changed_flags: InterfaceFlags,
    },
    AddressAdded {
        address: InterfaceAddress,
        origin: RequestOrigin,
    },
    AddressRemoved {
        address: InterfaceAddress,
        origin: RequestOrigin,
    },
    RouteAdded {
        route: RouteRecord,
        origin: RequestOrigin,
    },
    RouteRemoved {
        route: RouteRecord,
        origin: RequestOrigin,
    },
}

/// Delivers the events in order to the sockets that joined the groups they belong to.
///
/// Callers publish while they hold the lock that ordered the changes, so notifications reach every
/// socket in the order the changes happened.
pub(in crate::net) fn publish_network_events(events: Vec<NetworkEvent>) {
    for event in events {
        let (segment, group) = match &event {
            NetworkEvent::LinkChanged {
                iface,
                changed_flags,
            } => (
                RtnlSegment::NewLink(iface_to_new_link(
                    &notification_header(RequestOrigin::KERNEL),
                    iface,
                    changed_flags.bits(),
                )),
                LINK_GROUP,
            ),
            NetworkEvent::AddressAdded { address, origin } => (
                RtnlSegment::NewAddr(ipv4_to_addr(
                    &notification_header(*origin),
                    CSegmentType::NEWADDR,
                    address,
                )),
                IPV4_ADDRESS_GROUP,
            ),
            NetworkEvent::AddressRemoved { address, origin } => (
                RtnlSegment::DelAddr(ipv4_to_addr(
                    &notification_header(*origin),
                    CSegmentType::DELADDR,
                    address,
                )),
                IPV4_ADDRESS_GROUP,
            ),
            NetworkEvent::RouteAdded { route, origin } => {
                let mut segment =
                    record_to_route(&notification_header(*origin), CSegmentType::NEWROUTE, route);
                segment.header_mut().flags = (NewRequestFlags::CREATE | NewRequestFlags::EXCL).bits();
                (RtnlSegment::NewRoute(segment), IPV4_ROUTE_GROUP)
            }
            NetworkEvent::RouteRemoved { route, origin } => (
                RtnlSegment::DelRoute(record_to_route(
                    &notification_header(*origin),
                    CSegmentType::DELROUTE,
                    route,
                )),
                IPV4_ROUTE_GROUP,
            ),
        };

        let message = RtnlMessage::new(vec![segment]);
        debug!("netlink route notification: {:?}", message);
        NetlinkRouteProtocol::multicast(GroupIdSet::new(group), message).unwrap();
    }
}

fn notification_header(origin: RequestOrigin) -> CMsgSegHdr {
    CMsgSegHdr {
        len: 0,
        type_: 0,
        flags: 0,
        seq: origin.seq,
        pid: origin.pid,
    }
}
