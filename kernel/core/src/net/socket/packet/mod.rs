// SPDX-License-Identifier: MPL-2.0

//! This module defines packet sockets (`AF_PACKET`).
//!
//! A packet socket exchanges whole link-layer frames with a network interface. A raw packet
//! socket (`SOCK_RAW`) sees the link-layer header, and a cooked one (`SOCK_DGRAM`) sees only the
//! payload and names the peer by its link-layer address.
//!
//! A packet socket is selected by an EtherType and an interface. Both come from `socket(2)`
//! (EtherType only) and `bind(2)`. An EtherType of zero selects no frame, and an interface index of
//! zero selects every interface. Like Linux, only a socket that selects every EtherType
//! (`ETH_P_ALL`) sees the frames that the host sends.

mod addr;
mod tap;

pub(crate) use addr::{MAX_LINK_ADDR_LEN, PacketSocketAddr, PacketType};
use aster_bigtcp::iface::LinkTap;
use tap::PacketTap;

use crate::{
    events::IoEvents,
    fs::file::FileCommon,
    net::{
        iface::{Iface, iter_all_ifaces},
        socket::{
            Socket, new_socket_common,
            private::SocketPrivate,
            util::{
                MessageHeader, RecvFlags, RecvOutput, SendFlags, SocketAddr,
                options::check_current_net_raw,
            },
        },
    },
    prelude::*,
    process::signal::{PollHandle, Pollable, Pollee},
    util::{MultiRead, MultiWrite, net::SockType},
};

const ETH_P_ALL: u16 = 0x0003;
const ETHERNET_HEADER_LEN: usize = 14;

pub(crate) struct PacketSocket {
    tap: Arc<PacketTap>,
    registered: Mutex<Vec<Arc<Iface>>>,
    socket_type: SockType,

    pollee: Pollee,
    common: FileCommon,
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

        let pollee = Pollee::new();
        let socket = Arc::new(Self {
            tap: PacketTap::new(pollee.clone(), protocol),
            registered: Mutex::new(Vec::new()),
            socket_type,
            pollee,
            common: new_socket_common(is_nonblocking),
        });
        socket.register_with(None);

        Ok(socket)
    }

    /// Registers the tap with the selected interfaces and unregisters it from the others.
    fn register_with(&self, selected: Option<&Arc<Iface>>) {
        let mut registered = self.registered.lock();
        let tap: Arc<dyn LinkTap> = self.tap.clone();

        for iface in registered.drain(..) {
            iface.remove_link_tap(&tap);
        }
        for iface in iter_all_ifaces() {
            if selected.is_none_or(|selected| Arc::ptr_eq(selected, iface)) {
                iface.add_link_tap(tap.clone());
                registered.push(iface.clone());
            }
        }
    }

    fn try_recv(
        &self,
        writer: &mut dyn MultiWrite,
        flags: RecvFlags,
    ) -> Result<(RecvOutput, PacketSocketAddr)> {
        let frame = self.tap.dequeue(flags.receive_behavior().will_consume_data());
        self.pollee.invalidate();
        let frame = frame?;

        let payload_offset = match self.socket_type {
            SockType::SOCK_DGRAM => ETHERNET_HEADER_LEN,
            _ => 0,
        };
        let message = &frame.bytes()[payload_offset..];
        let copied_len = message.len().min(writer.sum_lens());
        writer
            .write(&mut VmReader::from(&message[..copied_len]))
            .map_err(|(err, _)| err)?;

        let output = RecvOutput::new_for_packet(flags, copied_len, message.len());
        Ok((output, frame.addr()))
    }
}

fn find_iface(ifindex: i32) -> Option<&'static Arc<Iface>> {
    iter_all_ifaces().find(|iface| iface.index() as i32 == ifindex)
}

impl Socket for PacketSocket {
    fn bind(&self, socket_addr: SocketAddr) -> Result<()> {
        let addr = PacketSocketAddr::try_from(socket_addr)?;

        let iface = match addr.ifindex() {
            0 => None,
            ifindex => Some(
                find_iface(ifindex)
                    .ok_or_else(|| Error::with_message(Errno::ENODEV, "the interface does not exist"))?,
            ),
        };

        let protocol = match addr.protocol() {
            0 => self.tap.protocol(),
            protocol => protocol,
        };
        self.register_with(iface);
        self.tap.rebind(
            protocol,
            addr.ifindex(),
            iface.is_none_or(|iface| iface.flags().contains(aster_bigtcp::iface::InterfaceFlags::UP)),
        );

        Ok(())
    }

    fn addr(&self) -> Result<SocketAddr> {
        let protocol = self.tap.protocol();
        let ifindex = self.tap.ifindex();

        let mut link_addr = [0u8; MAX_LINK_ADDR_LEN];
        let (hardware_type, link_addr_len) = match find_iface(ifindex) {
            Some(iface) => {
                let ether_addr = iface.ethernet_addr().map_or([0u8; 6], |addr| addr.0);
                link_addr[..ether_addr.len()].copy_from_slice(&ether_addr);
                (iface.type_() as u16, ether_addr.len() as u8)
            }
            None => (0, 0),
        };

        Ok(PacketSocketAddr::new(protocol, ifindex, hardware_type, 0, link_addr_len, link_addr).into())
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
        writer: &mut dyn MultiWrite,
        flags: RecvFlags,
    ) -> Result<(RecvOutput, MessageHeader)> {
        let (output, addr) = if flags.contains(RecvFlags::MSG_DONTWAIT) {
            self.try_recv(writer, flags)?
        } else {
            self.block_on(IoEvents::IN, None, || self.try_recv(writer, flags))?
        };

        Ok((output, MessageHeader::new(Some(addr.into()), Vec::new())))
    }

    fn common(&self) -> &FileCommon {
        &self.common
    }
}

impl Drop for PacketSocket {
    fn drop(&mut self) {
        let tap: Arc<dyn LinkTap> = self.tap.clone();
        for iface in self.registered.get_mut().drain(..) {
            iface.remove_link_tap(&tap);
        }
    }
}

impl SocketPrivate for PacketSocket {
    fn is_nonblocking(&self) -> bool {
        self.common.is_nonblocking()
    }
}

impl Pollable for PacketSocket {
    fn poll(&self, mask: IoEvents, poller: Option<&mut PollHandle>) -> IoEvents {
        self.pollee
            .poll_with(mask, poller, || self.tap.io_events())
    }
}
