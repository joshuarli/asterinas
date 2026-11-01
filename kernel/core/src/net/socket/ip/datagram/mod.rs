// SPDX-License-Identifier: MPL-2.0

use core::{
    sync::atomic::{AtomicU32, Ordering},
    time::Duration,
};

use aster_bigtcp::wire::{IpAddress, IpEndpoint};
use bound::{BoundDatagram, ReceivedMeta};
use unbound::{BindOptions, UnboundDatagram};

use super::{addr::UNSPECIFIED_LOCAL_ENDPOINT, ctrl_msg::IpControlMessage, ioctl::ipv4_ioctl};
use crate::{
    events::IoEvents,
    fs::file::FileCommon,
    net::{
        route::is_broadcast_endpoint,
        socket::{
            Socket,
            ip::{
                common::map_unspecified_to_localhost,
                options::{IpOptionSet, SetIpLevelOption},
            },
            new_socket_common,
            options::{Error as SocketError, SocketOption, macros::sock_option_mut},
            private::SocketPrivate,
            util::{
                ControlMessage, MessageHeader, RecvFlags, RecvOutput, SendFlags, SocketAddr,
                datagram_common::{Inner, select_remote_and_bind},
                options::{
                    GetSocketLevelOption, SetSocketLevelOption, SocketOptionSet, SocketTimeouts,
                    timestamping,
                },
            },
        },
    },
    prelude::*,
    process::signal::{PollHandle, Pollable, Pollee},
    util::{MultiRead, MultiWrite, ioctl::RawIoctl, net::SockType},
};

mod bound;
pub(super) mod observer;
mod unbound;

pub(crate) struct DatagramSocket {
    // Lock order: `inner` first, `options` second
    inner: RwMutex<Inner<UnboundDatagram, BoundDatagram>>,
    options: RwLock<OptionSet>,
    timeouts: SocketTimeouts,
    tx_timestamp_key: AtomicU32,

    pollee: Pollee,
    common: FileCommon,
}

#[derive(Clone, Debug)]
struct OptionSet {
    socket: SocketOptionSet,
    ip: IpOptionSet,
    // TODO: UDP option set
}

impl OptionSet {
    fn new() -> Self {
        let socket = SocketOptionSet::new_udp();
        let ip = IpOptionSet::new_udp();
        OptionSet { socket, ip }
    }
}

impl DatagramSocket {
    pub(crate) fn new(is_nonblocking: bool) -> Arc<Self> {
        let unbound_datagram = UnboundDatagram::new();
        Arc::new(Self {
            inner: RwMutex::new(Inner::Unbound(unbound_datagram)),
            options: RwLock::new(OptionSet::new()),
            timeouts: SocketTimeouts::new(),
            tx_timestamp_key: AtomicU32::new(0),
            pollee: Pollee::new(),
            common: new_socket_common(is_nonblocking),
        })
    }

    fn try_recv(
        &self,
        writer: &mut dyn MultiWrite,
        flags: RecvFlags,
    ) -> Result<(RecvOutput, ReceivedMeta, u32)> {
        let result = match &*self.inner.read() {
            Inner::Unbound(_) => {
                return_errno_with_message!(Errno::EAGAIN, "the socket is not bound")
            }
            Inner::Bound(bound_datagram) => {
                let (output, meta) = bound_datagram.try_recv_with_meta(writer, flags)?;
                (output, meta, bound_datagram.iface().index())
            }
        };
        self.pollee.invalidate();

        Ok(result)
    }

    /// Builds the control messages a received datagram carries, as the socket options ask.
    fn received_control_messages(
        &self,
        meta: &ReceivedMeta,
        ifindex: u32,
    ) -> Vec<ControlMessage> {
        let options = self.options.read();
        let mut messages = Vec::new();

        if options.socket.recv_timestamp_ns() {
            messages.push(ControlMessage::Ip(IpControlMessage::TimestampNs(
                meta.arrived_at,
            )));
        } else if options.socket.recv_timestamp() {
            messages.push(ControlMessage::Ip(IpControlMessage::Timestamp(
                meta.arrived_at,
            )));
        }

        let flags = options.socket.timestamping();
        if flags & timestamping::RX_SOFTWARE != 0 && flags & timestamping::SOFTWARE != 0 {
            messages.push(ControlMessage::Ip(IpControlMessage::Timestamping(
                meta.arrived_at,
            )));
        }

        if options.ip.pktinfo()
            && let Some(IpAddress::Ipv4(address)) = meta.local_address
        {
            messages.push(ControlMessage::Ip(IpControlMessage::PacketInfo {
                ifindex: ifindex as i32,
                local: address.octets(),
                destination: address.octets(),
            }));
        }

        messages
    }

    /// Takes one pending transmit timestamp, as `recvmsg(MSG_ERRQUEUE)` does.
    fn recv_error_queue(&self, flags: RecvFlags) -> Result<(RecvOutput, MessageHeader)> {
        let stamp = match &*self.inner.read() {
            Inner::Bound(bound_datagram) => bound_datagram.pop_tx_timestamp(),
            Inner::Unbound(_) => None,
        }
        .ok_or_else(|| Error::with_message(Errno::EAGAIN, "the error queue is empty"))?;
        self.pollee.invalidate();

        let tx_id = stamp.tag.wrapping_sub(1);
        let time = Duration::from_nanos(stamp.wall_time_ns);
        let messages = vec![
            ControlMessage::Ip(IpControlMessage::Timestamping(time)),
            ControlMessage::Ip(IpControlMessage::TimestampingError { tx_id }),
        ];
        let output = RecvOutput::new_for_packet(flags, 0, 0);

        Ok((output, MessageHeader::new(None, messages)))
    }

    fn try_send(
        &self,
        reader: &mut dyn MultiRead,
        remote: Option<&IpEndpoint>,
        flags: SendFlags,
    ) -> Result<usize> {
        let tx_tag = self.next_tx_tag();
        let (sent_bytes, iface_to_poll) = select_remote_and_bind(
            &self.inner,
            remote,
            || {
                let remote_endpoint = remote.ok_or_else(|| {
                    Error::with_message(
                        Errno::EDESTADDRREQ,
                        "the destination address is not specified",
                    )
                })?;
                self.inner
                    .write()
                    .bind_ephemeral(remote_endpoint, &self.pollee)
            },
            |bound_datagram, remote_endpoint| {
                let sent_bytes = bound_datagram.try_send_tagged(reader, remote_endpoint, tx_tag)?;
                let iface_to_poll = bound_datagram.iface().clone();
                Ok((sent_bytes, iface_to_poll))
            },
        )?;

        self.pollee.invalidate();
        iface_to_poll.poll();

        Ok(sent_bytes)
    }
}

impl DatagramSocket {
    /// Returns the tag that asks for a transmit timestamp, or zero when none is requested.
    ///
    /// The tag is the timestamp key plus one, so that it is never zero.
    fn next_tx_tag(&self) -> u32 {
        let flags = self.options.read().socket.timestamping();
        if flags & timestamping::TX_SOFTWARE == 0 || flags & timestamping::SOFTWARE == 0 {
            return 0;
        }
        if flags & timestamping::OPT_ID == 0 {
            return 1;
        }
        self.tx_timestamp_key
            .fetch_add(1, Ordering::Relaxed)
            .wrapping_add(1)
    }
}

impl Pollable for DatagramSocket {
    fn poll(&self, mask: IoEvents, poller: Option<&mut PollHandle>) -> IoEvents {
        self.pollee
            .poll_with(mask, poller, || self.inner.read().check_io_events())
    }
}

impl SocketPrivate for DatagramSocket {
    fn is_nonblocking(&self) -> bool {
        self.common.is_nonblocking()
    }

    fn protocol_ioctl(&self, raw_ioctl: RawIoctl) -> Result<i32> {
        // Handle common IPv4/IPv6 ioctl commands.
        // TODO: Handle IPv6 ioctls once UDP sockets support IPv6.
        ipv4_ioctl(raw_ioctl)

        // Handle ioctl commands that require UDP-specific handling.
    }
}

impl Socket for DatagramSocket {
    fn bind(&self, socket_addr: SocketAddr) -> Result<()> {
        let endpoint = socket_addr.try_into()?;
        let can_reuse = self.options.read().socket.reuse_addr();

        self.inner
            .write()
            .bind(&endpoint, &self.pollee, BindOptions { can_reuse })
    }

    fn connect(&self, socket_addr: SocketAddr) -> Result<()> {
        let endpoint = map_unspecified_to_localhost(socket_addr.try_into()?);
        let can_broadcast = self.options.read().socket.broadcast();
        if !can_broadcast && is_broadcast_endpoint(&endpoint) {
            return_errno_with_message!(
                Errno::EACCES,
                "connecting to a broadcast address without SO_BROADCAST is not allowed"
            );
        }

        self.inner.write().connect(&endpoint, &self.pollee)
    }

    fn addr(&self) -> Result<SocketAddr> {
        let endpoint = self
            .inner
            .read()
            .addr()
            .unwrap_or(UNSPECIFIED_LOCAL_ENDPOINT);

        Ok(endpoint.into())
    }

    fn peer_addr(&self) -> Result<SocketAddr> {
        let endpoint =
            *self.inner.read().peer_addr().ok_or_else(|| {
                Error::with_message(Errno::ENOTCONN, "the socket is not connected")
            })?;

        Ok(endpoint.into())
    }

    fn sendmsg(
        &self,
        reader: &mut dyn MultiRead,
        message_header: MessageHeader,
        flags: SendFlags,
    ) -> Result<usize> {
        // TODO: Deal with flags
        if !flags.is_all_supported() {
            warn!("unsupported flags: {:?}", flags);
        }

        let MessageHeader {
            addr,
            control_messages,
        } = message_header;

        let endpoint = match addr {
            Some(addr) => Some(addr.try_into()?),
            None => None,
        };

        if let Some(endpoint) = endpoint.as_ref() {
            let can_broadcast = self.options.read().socket.broadcast();
            if !can_broadcast && is_broadcast_endpoint(endpoint) {
                return_errno_with_message!(
                    Errno::EACCES,
                    "sending to a broadcast address without SO_BROADCAST is not allowed"
                );
            }
        }

        if !control_messages.is_empty() {
            // TODO: Support sending control message
            warn!("sending control message is not supported");
        }

        // TODO: Block if the send buffer is full
        self.try_send(reader, endpoint.as_ref(), flags)
    }

    fn recvmsg(
        &self,
        writer: &mut dyn MultiWrite,
        flags: RecvFlags,
    ) -> Result<(RecvOutput, MessageHeader)> {
        // TODO: Deal with flags
        if !flags.is_all_supported() {
            warn!("unsupported flags: {:?}", flags);
        }

        if flags.contains(RecvFlags::MSG_ERRQUEUE) {
            return self.recv_error_queue(flags);
        }

        let (output, meta, ifindex) =
            self.block_on(IoEvents::IN, self.timeouts.recv_timeout(), || {
                self.try_recv(writer, flags)
            })?;

        let control_messages = self.received_control_messages(&meta, ifindex);
        let message_header = MessageHeader::new(Some(meta.remote.into()), control_messages);

        Ok((output, message_header))
    }

    fn get_option(&self, option: &mut dyn SocketOption) -> Result<()> {
        sock_option_mut!(match option {
            socket_errors @ SocketError => {
                // TODO: Support socket errors for UDP sockets
                socket_errors.set(None);
                return Ok(());
            }
            _ => (),
        });

        let inner = self.inner.read();
        let options = self.options.read();

        // Deal with socket-level options
        match options
            .socket
            .get_option(option, &(&*inner, &self.timeouts))
        {
            Err(err) if err.error() == Errno::ENOPROTOOPT => (),
            res => return res,
        }

        // Deal with IP-level options
        options.ip.get_option(option)
    }

    fn set_option(&self, option: &dyn SocketOption) -> Result<()> {
        let inner = self.inner.read();
        let mut options = self.options.write();

        // Deal with socket-level options
        let need_iface_poll = match options
            .socket
            .set_option(option, &(&*inner, &self.timeouts))
        {
            Err(err) if err.error() == Errno::ENOPROTOOPT => {
                // Deal with IP-level options
                options.ip.set_option(option, &*inner)?
            }
            Err(err) => return Err(err),
            Ok(need_iface_poll) => need_iface_poll,
        };

        let iface_to_poll = need_iface_poll
            .then(|| match &*inner {
                Inner::Unbound(_) => None,
                Inner::Bound(bound_datagram) => Some(bound_datagram.iface().clone()),
            })
            .flatten();

        drop(inner);
        drop(options);

        if let Some(iface) = iface_to_poll {
            iface.poll();
        }

        Ok(())
    }

    fn common(&self) -> &FileCommon {
        &self.common
    }
}

impl GetSocketLevelOption for (&Inner<UnboundDatagram, BoundDatagram>, &SocketTimeouts) {
    fn socket_type(&self) -> SockType {
        SockType::SOCK_DGRAM
    }

    fn is_listening(&self) -> bool {
        false
    }

    fn socket_timeouts(&self) -> Option<&SocketTimeouts> {
        Some(self.1)
    }
}

impl SetSocketLevelOption for (&Inner<UnboundDatagram, BoundDatagram>, &SocketTimeouts) {
    fn set_reuse_addr(&self, reuse_addr: bool) {
        let Inner::Bound(bound) = self.0 else {
            return;
        };

        bound.bound_port().set_can_reuse(reuse_addr);
    }

    fn socket_timeouts(&self) -> Option<&SocketTimeouts> {
        Some(self.1)
    }
}

impl SetIpLevelOption for Inner<UnboundDatagram, BoundDatagram> {
    fn set_hdrincl(&self, _hdrincl: bool) -> Result<()> {
        return_errno_with_message!(
            Errno::ENOPROTOOPT,
            "IP_HDRINCL cannot be set on UDP sockets"
        );
    }
}
