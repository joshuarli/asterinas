// SPDX-License-Identifier: MPL-2.0

use super::CSocketAddrFamily;
use crate::{
    net::socket::packet::{MAX_LINK_ADDR_LEN, PacketSocketAddr},
    prelude::*,
};

/// Packet socket address (`struct sockaddr_ll`).
#[repr(C)]
#[derive(Clone, Copy, Debug, Pod)]
pub(crate) struct CSocketAddrPacket {
    /// Address family (AF_PACKET).
    sll_family: u16,
    /// The EtherType in network byte order.
    sll_protocol: u16,
    sll_ifindex: i32,
    sll_hatype: u16,
    sll_pkttype: u8,
    sll_halen: u8,
    sll_addr: [u8; MAX_LINK_ADDR_LEN],
}

impl CSocketAddrPacket {
    /// The length of the address when it carries `link_addr_len` link-layer address bytes.
    pub(crate) fn len_with_link_addr(link_addr_len: u8) -> usize {
        core::mem::offset_of!(Self, sll_addr) + (link_addr_len as usize).min(MAX_LINK_ADDR_LEN)
    }
}

impl From<PacketSocketAddr> for CSocketAddrPacket {
    fn from(value: PacketSocketAddr) -> Self {
        Self {
            sll_family: CSocketAddrFamily::AF_PACKET as _,
            sll_protocol: value.protocol().to_be(),
            sll_ifindex: value.ifindex(),
            sll_hatype: value.hardware_type(),
            sll_pkttype: value.packet_type(),
            sll_halen: value.link_addr_len(),
            sll_addr: *value.link_addr(),
        }
    }
}

impl From<CSocketAddrPacket> for PacketSocketAddr {
    fn from(value: CSocketAddrPacket) -> Self {
        debug_assert_eq!(value.sll_family, CSocketAddrFamily::AF_PACKET as u16);
        PacketSocketAddr::new(
            u16::from_be(value.sll_protocol),
            value.sll_ifindex,
            value.sll_hatype,
            value.sll_pkttype,
            value.sll_halen,
            value.sll_addr,
        )
    }
}
