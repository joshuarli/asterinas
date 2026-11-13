// SPDX-License-Identifier: MPL-2.0

//! TCP socket identity, state and queue diagnostics.
//!
//! Timer and retransmission telemetry are unavailable and carry zero in the
//! base reply. Optional memory and TCP_INFO attributes are not exposed.

use crate::net::socket::netlink::{common::NetlinkSocket, table::NetlinkSockDiagProtocol};

mod bound;
mod controller;
mod message;

pub(super) use message::SockDiagMessage;
pub(crate) type NetlinkSockDiagSocket = NetlinkSocket<NetlinkSockDiagProtocol>;
