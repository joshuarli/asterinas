// SPDX-License-Identifier: MPL-2.0

use crate::{net::socket::util::SocketAddr, prelude::*};

/// The maximum length of a link-layer address in a packet socket address.
pub(crate) const MAX_LINK_ADDR_LEN: usize = 8;

/// The address of a packet socket (`struct sockaddr_ll`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PacketSocketAddr {
    /// The EtherType in host byte order; zero means none.
    protocol: u16,
    /// The interface index; zero means any interface.
    ifindex: i32,
    hardware_type: u16,
    packet_type: u8,
    link_addr_len: u8,
    link_addr: [u8; MAX_LINK_ADDR_LEN],
}

impl PacketSocketAddr {
    pub(crate) const fn new(
        protocol: u16,
        ifindex: i32,
        hardware_type: u16,
        packet_type: u8,
        link_addr_len: u8,
        link_addr: [u8; MAX_LINK_ADDR_LEN],
    ) -> Self {
        Self {
            protocol,
            ifindex,
            hardware_type,
            packet_type,
            link_addr_len,
            link_addr,
        }
    }

    pub(crate) const fn protocol(&self) -> u16 {
        self.protocol
    }

    pub(crate) const fn ifindex(&self) -> i32 {
        self.ifindex
    }

    pub(crate) const fn hardware_type(&self) -> u16 {
        self.hardware_type
    }

    pub(crate) const fn packet_type(&self) -> u8 {
        self.packet_type
    }

    pub(crate) const fn link_addr_len(&self) -> u8 {
        self.link_addr_len
    }

    pub(crate) const fn link_addr(&self) -> &[u8; MAX_LINK_ADDR_LEN] {
        &self.link_addr
    }
}

impl TryFrom<SocketAddr> for PacketSocketAddr {
    type Error = Error;

    fn try_from(value: SocketAddr) -> Result<Self> {
        match value {
            SocketAddr::Packet(addr) => Ok(addr),
            _ => return_errno_with_message!(
                Errno::EINVAL,
                "the address is not a packet socket address"
            ),
        }
    }
}

impl From<PacketSocketAddr> for SocketAddr {
    fn from(value: PacketSocketAddr) -> Self {
        SocketAddr::Packet(value)
    }
}
