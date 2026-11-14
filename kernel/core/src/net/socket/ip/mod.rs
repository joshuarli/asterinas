// SPDX-License-Identifier: MPL-2.0

use alloc::vec::Vec;

mod addr;
mod common;
mod ctrl_msg;
mod datagram;
mod ioctl;
pub(crate) mod options;
mod stream;
mod packet;
mod ping_group;

pub(crate) use addr::IpAddressFamily;
pub(crate) use ctrl_msg::IpControlMessage;
pub(crate) use datagram::DatagramSocket;
pub(crate) use packet::IpPacketSocket;
pub(crate) use ping_group::{ping_group_range, set_ping_group_range};
pub(in crate::net) use datagram::observer::DatagramObserver;
pub(in crate::net) use stream::observer::StreamObserver;
pub(crate) use stream::{StreamSocket, options as stream_options};

pub(crate) fn proc_tcp_page(iface: usize, offset: usize, limit: usize) -> Option<Vec<aster_bigtcp::diagnostic::TcpSocketSnapshot>> {
    crate::net::iface::iter_all_ifaces().nth(iface).map(|iface| iface.common().tcp_snapshots(offset, limit))
}

pub(crate) fn proc_udp_page(cursor: Option<aster_bigtcp::iface::UdpSnapshotCursor>, limit: usize) -> (Option<aster_bigtcp::iface::UdpSnapshotCursor>, Vec<aster_bigtcp::diagnostic::UdpSocketSnapshot>) {
    crate::net::iface::network_registry().udp_snapshot_page(cursor, limit)
}
