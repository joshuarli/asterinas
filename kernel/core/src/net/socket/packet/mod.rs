// SPDX-License-Identifier: MPL-2.0

//! This module defines packet sockets (`AF_PACKET`).
//!
//! A packet socket exchanges whole link-layer frames with a network interface. A raw packet
//! socket (`SOCK_RAW`) sees the link-layer header, and a cooked one (`SOCK_DGRAM`) sees only the
//! payload and names the peer by its link-layer address.
//!
//! A packet socket is selected by an EtherType and an interface. Both come from `socket(2)`
//! (EtherType only) and `bind(2)`. An EtherType of zero selects no frame, and an interface index of
//! zero selects every interface.

mod addr;

pub(crate) use addr::{MAX_LINK_ADDR_LEN, PacketSocketAddr};

use crate::{
    events::IoEvents,
    fs::file::FileCommon,
    net::{
        iface::{Iface, iter_all_ifaces},
        socket::{
            Socket, new_socket_common,
            private::SocketPrivate,
            util::{
                MessageHeader, RecvFlags, RecvOutput, SendFlags, SocketAddr, options::check_current_net_raw,
            },
        },
    },
    prelude::*,
    process::signal::{PollHandle, Pollable, Pollee},
    util::{MultiRead, MultiWrite, net::SockType},
};

pub(crate) struct PacketSocket {
    binding: Mutex<Binding>,
    socket_type: SockType,

    pollee: Pollee,
    common: FileCommon,
}

#[derive(Clone, Copy, Debug)]
struct Binding {
    protocol: u16,
    ifindex: i32,
}

impl PacketSocket {
    pub(crate) fn create(
        is_nonblocking: bool,
        socket_type: SockType,
        protocol: u16,
    ) -> Result<Arc<Self>> {
        check_current_net_raw()?;
        if socket_type != SockType::SOCK_RAW && socket_type != SockType::SOCK_DGRAM {
            return_errno_with_message!(
                Errno::ESOCKTNOSUPPORT,
                "the packet socket type is not supported"
            );
        }

        Ok(Arc::new(Self {
            binding: Mutex::new(Binding {
                protocol,
                ifindex: 0,
            }),
            socket_type,
            pollee: Pollee::new(),
            common: new_socket_common(is_nonblocking),
        }))
    }
}

fn find_iface(ifindex: i32) -> Option<&'static Arc<Iface>> {
    iter_all_ifaces().find(|iface| iface.index() as i32 == ifindex)
}

impl Socket for PacketSocket {
    fn bind(&self, socket_addr: SocketAddr) -> Result<()> {
        let addr = PacketSocketAddr::try_from(socket_addr)?;

        if addr.ifindex() != 0 && find_iface(addr.ifindex()).is_none() {
            return_errno_with_message!(Errno::ENODEV, "the interface does not exist");
        }

        let mut binding = self.binding.lock();
        if addr.protocol() != 0 {
            binding.protocol = addr.protocol();
        }
        binding.ifindex = addr.ifindex();

        Ok(())
    }

    fn addr(&self) -> Result<SocketAddr> {
        let binding = *self.binding.lock();

        let mut link_addr = [0u8; MAX_LINK_ADDR_LEN];
        let (hardware_type, link_addr_len) = match find_iface(binding.ifindex) {
            Some(iface) => {
                let ether_addr = iface.ethernet_addr().map_or([0u8; 6], |addr| addr.0);
                link_addr[..ether_addr.len()].copy_from_slice(&ether_addr);
                (iface.type_() as u16, ether_addr.len() as u8)
            }
            None => (0, 0),
        };

        Ok(PacketSocketAddr::new(
            binding.protocol,
            binding.ifindex,
            hardware_type,
            0,
            link_addr_len,
            link_addr,
        )
        .into())
    }

    fn sendmsg(
        &self,
        _reader: &mut dyn MultiRead,
        _message_header: MessageHeader,
        _flags: SendFlags,
    ) -> Result<usize> {
        return_errno_with_message!(Errno::EOPNOTSUPP, "sending on packet sockets is not supported");
    }

    fn recvmsg(
        &self,
        _writer: &mut dyn MultiWrite,
        _flags: RecvFlags,
    ) -> Result<(RecvOutput, MessageHeader)> {
        return_errno_with_message!(
            Errno::EOPNOTSUPP,
            "receiving on packet sockets is not supported"
        );
    }

    fn common(&self) -> &FileCommon {
        &self.common
    }
}

impl SocketPrivate for PacketSocket {
    fn is_nonblocking(&self) -> bool {
        self.common.is_nonblocking()
    }
}

impl Pollable for PacketSocket {
    fn poll(&self, mask: IoEvents, poller: Option<&mut PollHandle>) -> IoEvents {
        self.pollee.poll_with(mask, poller, || IoEvents::OUT)
    }
}
