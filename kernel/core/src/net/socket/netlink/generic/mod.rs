// SPDX-License-Identifier: MPL-2.0

use crate::net::socket::netlink::{common::NetlinkSocket, table::NetlinkGenericProtocol};

mod bound;
mod controller;
mod message;

pub(super) use message::GenericMessage;
pub(crate) type NetlinkGenericSocket = NetlinkSocket<NetlinkGenericProtocol>;
