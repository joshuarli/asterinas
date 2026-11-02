// SPDX-License-Identifier: MPL-2.0

use crate::{net::socket::options::macros::impl_socket_options, prelude::*};

/// The counters that `PACKET_STATISTICS` reports (`struct tpacket_stats`).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Pod)]
pub(crate) struct PacketStatistics {
    /// The frames that matched the socket, including the dropped ones.
    pub(crate) packets: u32,
    /// The frames that did not fit in the receive queue.
    pub(crate) drops: u32,
}

impl_socket_options!(
    pub(crate) struct IgnoreOutgoing(bool);
    pub(crate) struct Statistics(PacketStatistics);
);
