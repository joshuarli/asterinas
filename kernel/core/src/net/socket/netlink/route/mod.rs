// SPDX-License-Identifier: MPL-2.0

//! Netlink Route Socket.

pub(in crate::net) use kernel::notify::{NetworkEvent, RequestOrigin, publish_network_events};
pub(super) use message::RtnlMessage;

use crate::net::socket::netlink::{common::NetlinkSocket, table::NetlinkRouteProtocol};

mod bound;
mod kernel;
mod message;

pub(crate) type NetlinkRouteSocket = NetlinkSocket<NetlinkRouteProtocol>;
