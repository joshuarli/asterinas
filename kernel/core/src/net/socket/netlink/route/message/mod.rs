// SPDX-License-Identifier: MPL-2.0

//! Netlink message types for the netlink route protocol.
//!
//! This module defines how to interpret messages sent from user space and how to write
//! kernel messages back to user space.

#![short_vis_path::add(netlink)]

mod attr;
mod segment;

pub(super) use attr::{
    addr::{AddrAttr, AddrCacheInfo, AddrProtocol, INFINITE_LIFETIME},
    link::{CLinkStats64, LinkAttr, OperState, RtExtFilter},
    route::RouteAttr,
    rule::RuleAttr,
};
pub(super) use segment::{
    RtnlSegment,
    addr::{AddrMessageFlags, AddrSegment, AddrSegmentBody, RtScope},
    link::{LinkSegment, LinkSegmentBody},
    route::{RouteSegment, RouteSegmentBody},
    rule::{RuleSegment, RuleSegmentBody},
};

use crate::net::socket::netlink::{message::Message, table::MulticastMessage};

/// A netlink route message.
pub(in netlink) type RtnlMessage = Message<RtnlSegment>;

impl MulticastMessage for RtnlMessage {}
