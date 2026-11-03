// SPDX-License-Identifier: MPL-2.0

use core::{
    sync::atomic::{AtomicU32, Ordering},
    time::Duration,
};

use aster_bigtcp::{socket::UdpErrorOrigin, wire::{IpAddress, IpEndpoint}};
use bound::{BoundDatagram, ReceivedMeta};
use unbound::{BindOptions, UnboundDatagram};

use super::{addr::UNSPECIFIED_LOCAL_ENDPOINT, ctrl_msg::IpControlMessage, ioctl::ipv4_ioctl};
use crate::{
    events::IoEvents,
    fs::file::FileCommon,
    net::{
        iface::{Iface, iter_all_ifaces},
        route::{is_broadcast_endpoint, lookup_direct_iface, lookup_iface},
        socket::{
            Socket,
            ip::{
                common::{get_ephemeral_endpoint_on, map_unspecified_to_localhost},
                options::{IpOptionSet, SetIpLevelOption},
            },
            new_udp_socket_common,
            options::{
                BindToDevice, DontRoute, Error as SocketError, ReusePort, SocketOption,
                macros::{sock_option_mut, sock_option_ref},
            },
            private::SocketPrivate,
            util::{
                BoundDevice, ControlMessage, MessageHeader, RecvFlags, RecvOutput, SendFlags,
                SocketAddr,
                datagram_common::{Bound, Inner, select_remote_and_bind},
                options::{
                    GetSocketLevelOption, SetSocketLevelOption, SocketOptionSet, SocketTimeouts,
                    check_current_net_raw, timestamping,
                },
            },
        },
    },
    prelude::*,
    process::{posix_thread::AsPosixThread, signal::{PollHandle, Pollable, Pollee}},
    util::{MultiRead, MultiWrite, ioctl::RawIoctl, net::SockType},
};

mod bound;
pub(super) mod observer;
mod unbound;

const SO_EE_ORIGIN_ICMP: u8 = 2;
const IPV4_MAX_UDP_PAYLOAD: usize = u16::MAX as usize - 20 - 8;

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
    device: BoundDevice,
    dont_route: bool,
    // TODO: UDP option set
}

impl OptionSet {
    fn new() -> Self {
        let socket = SocketOptionSet::new_udp();
        let ip = IpOptionSet::new_udp();
        OptionSet {
            socket,
            ip,
            device: BoundDevice::NONE,
            dont_route: false,
        }
    }
}

impl DatagramSocket {
    fn take_pending_error(&self) -> Option<Error> {
        let origin = match &*self.inner.read() {
            Inner::Bound(bound) => bound.take_pending_error(),
            Inner::Unbound(_) => None,
        };
        if origin.is_some() {
            self.pollee.invalidate();
        }
        origin.map(|origin| Error::from(network_error_errno(origin)))
    }

    pub(crate) fn new(is_nonblocking: bool) -> Arc<Self> {
        let credentials = current_thread!().as_posix_thread().unwrap().credentials();
        let (common, owner) = new_udp_socket_common(is_nonblocking, credentials.fsuid(), credentials.fsgid());
        let unbound_datagram = UnboundDatagram::new(owner);
        Arc::new(Self {
            inner: RwMutex::new(Inner::Unbound(unbound_datagram)),
            options: RwLock::new(OptionSet::new()),
            timeouts: SocketTimeouts::new(),
            tx_timestamp_key: AtomicU32::new(0),
            pollee: Pollee::new(),
            common,
        })
    }

    fn try_recv(
        &self,
        writer: &mut dyn MultiWrite,
        flags: RecvFlags,
    ) -> Result<(RecvOutput, ReceivedMeta, u32)> {
        if let Some(error) = self.take_pending_error() {
            return Err(error);
        }
        let result = match &*self.inner.read() {
            Inner::Unbound(_) => {
                return_errno_with_message!(Errno::EAGAIN, "the socket is not bound")
            }
            Inner::Bound(bound_datagram) => {
                let (output, meta) = bound_datagram.try_recv_with_meta(writer, flags)?;
                let ifindex = meta.ifindex;
                (output, meta, ifindex)
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

        if options.ip.recvttl() {
            messages.push(ControlMessage::Ip(IpControlMessage::TimeToLive(meta.ttl)));
        }
        if options.ip.recvtos() {
            messages.push(ControlMessage::Ip(IpControlMessage::TypeOfService(meta.tos)));
        }

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
    fn recv_error_queue(
        &self,
        writer: &mut dyn MultiWrite,
        flags: RecvFlags,
    ) -> Result<(RecvOutput, MessageHeader)> {
        let network_error = match &*self.inner.read() {
            Inner::Bound(bound) => bound.pop_network_error(),
            Inner::Unbound(_) => None,
        };
        if let Some(error) = network_error {
            self.pollee.invalidate();
            let copied = writer.write(&mut VmReader::from(error.payload.as_slice()))?;
            let (origin, type_, code, info, offender) = match error.origin {
                UdpErrorOrigin::Icmp { offender: IpAddress::Ipv4(addr), type_, code, info, .. } =>
                    (SO_EE_ORIGIN_ICMP, type_, code, info, Some(addr.octets())),
                UdpErrorOrigin::Icmp { type_, code, info, .. } => (SO_EE_ORIGIN_ICMP, type_, code, info, None),
            };
            let message = IpControlMessage::NetworkError {
                errno: network_error_errno(error.origin) as u32,
                origin, type_, code, info, offender,
            };
            let mut messages = Vec::new();
            let options = self.options.read();
            let time = Duration::from_nanos(error.timestamp_ns);
            if options.ip.recvttl()
                && let UdpErrorOrigin::Icmp { ttl, .. } = error.origin
            {
                messages.push(ControlMessage::Ip(IpControlMessage::TimeToLive(ttl)));
            }
            if options.ip.recvtos()
                && let UdpErrorOrigin::Icmp { tos, .. } = error.origin
            {
                messages.push(ControlMessage::Ip(IpControlMessage::TypeOfService(tos)));
            }
            if options.socket.recv_timestamp_ns() {
                messages.push(ControlMessage::Ip(IpControlMessage::TimestampNs(time)));
            } else if options.socket.recv_timestamp() {
                messages.push(ControlMessage::Ip(IpControlMessage::Timestamp(time)));
            }
            messages.push(ControlMessage::Ip(message));
            let output = RecvOutput::new_for_error_queue(flags, copied, error.payload.len());
            return Ok((output, MessageHeader::new(Some(error.destination.into()), messages)));
        }
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
        let output = RecvOutput::new_for_error_queue(flags, 0, 0);

        Ok((output, MessageHeader::new(None, messages)))
    }

    fn try_send(
        &self,
        reader: &mut dyn MultiRead,
        remote: Option<&IpEndpoint>,
        flags: SendFlags,
    ) -> Result<usize> {
        if let Some(error) = self.take_pending_error() {
            return Err(error);
        }
        if reader.sum_lens() > IPV4_MAX_UDP_PAYLOAD {
            return_errno_with_message!(Errno::EMSGSIZE, "the UDP datagram exceeds the IPv4 length limit");
        }
        let tx_tag = self.next_tx_tag();
        let (tos, dont_route) = {
            let options = self.options.read();
            (options.ip.tos(), options.dont_route || flags.contains(SendFlags::MSG_DONTROUTE))
        };
        let (sent_bytes, iface_to_poll) = select_remote_and_bind(
            &self.inner,
            remote,
            || {
                remote.ok_or_else(|| {
                    Error::with_message(
                        Errno::EDESTADDRREQ,
                        "the destination address is not specified",
                    )
                })?;
                self.bind_ephemeral()
            },
            |bound_datagram, remote_endpoint| {
                let remote_endpoint = map_unspecified_to_localhost(*remote_endpoint);
                let iface = self.output_iface(&remote_endpoint, dont_route)?;
                let local = bound_datagram.local_endpoint();
                let source = if local.addr.is_unspecified() || is_broadcast_endpoint(&local) {
                    get_ephemeral_endpoint_on(&iface, &remote_endpoint)?.addr
                } else {
                    local.addr
                };
                let sent_bytes = bound_datagram.try_send_tagged(reader, &remote_endpoint, &iface, source, tx_tag, tos)?;
                Ok((sent_bytes, iface))
            },
        )?;

        self.pollee.invalidate();
        iface_to_poll.poll();

        Ok(sent_bytes)
    }
}

impl DatagramSocket {
    fn bind_ephemeral(&self) -> Result<()> {
        let (device, can_reuse, reuse_port) = {
            let options = self.options.read();
            (options.device, options.socket.reuse_addr(), options.socket.reuse_port())
        };
        let mut inner = self.inner.write();
        if matches!(&*inner, Inner::Unbound(_)) {
            inner.bind(&UNSPECIFIED_LOCAL_ENDPOINT, &self.pollee, BindOptions { can_reuse, reuse_port, device })?;
        }
        if let Inner::Bound(bound) = &*inner {
            let options = self.options.read();
            bound.set_receive_errors(options.ip.recverr());
            bound.set_hop_limit(options.ip.ttl().get());
        }
        Ok(())
    }

    fn output_iface(&self, remote: &IpEndpoint, dont_route: bool) -> Result<Arc<Iface>> {
        let device = self.options.read().device;
        let route = if dont_route { Some(lookup_direct_iface(remote.addr)?) } else { None };
        match (device.iface()?, route) {
            (Some(device), Some(route)) if !Arc::ptr_eq(device, &route) => {
                return_errno_with_message!(Errno::ENETUNREACH, "the direct route uses a different interface");
            }
            (Some(device), _) => Ok(device.clone()),
            (None, Some(route)) => Ok(route),
            (None, None) => lookup_iface(remote.addr),
        }
    }

    fn set_bound_device(&self, device: BoundDevice) -> Result<()> {
        let inner = self.inner.read();
        let mut options = self.options.write();

        if options.device == device {
            return Ok(());
        }
        if options.device.is_bound() {
            check_current_net_raw()?;
        }
        if matches!(&*inner, Inner::Bound(_)) {
            return_errno_with_message!(
                Errno::EOPNOTSUPP,
                "a bound socket cannot change the device it is restricted to"
            );
        }

        options.device = device;
        Ok(())
    }

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
        let (can_reuse, reuse_port, device) = {
            let options = self.options.read();
            (options.socket.reuse_addr(), options.socket.reuse_port(), options.device)
        };

        let mut inner = self.inner.write();
        inner.bind(
            &endpoint,
            &self.pollee,
            BindOptions { can_reuse, reuse_port, device },
        )?;
        if let Inner::Bound(bound) = &*inner {
            let options = self.options.read();
            bound.set_receive_errors(options.ip.recverr());
            bound.set_hop_limit(options.ip.ttl().get());
        }
        Ok(())
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

        let dont_route = self.options.read().dont_route;
        self.bind_ephemeral()?;
        let iface = self.output_iface(&endpoint, dont_route)?;
        let mut inner = self.inner.write();
        if let Inner::Bound(bound) = &mut *inner {
            if bound.bound_port().endpoint().addr.is_unspecified() {
                bound.set_connected_source(get_ephemeral_endpoint_on(&iface, &endpoint)?.addr);
            }
        }
        inner.connect(&endpoint, &self.pollee)
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
        if !(flags & !SendFlags::MSG_DONTROUTE).is_all_supported() {
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
            return self.recv_error_queue(writer, flags);
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
                socket_errors.set(self.take_pending_error());
                return Ok(());
            }
            bind_to_device @ BindToDevice => {
                bind_to_device.set(self.options.read().device);
                return Ok(());
            }
            dont_route @ DontRoute => {
                dont_route.set(self.options.read().dont_route);
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
        sock_option_ref!(match option {
            bind_to_device @ BindToDevice => {
                return self.set_bound_device(*bind_to_device.get().unwrap());
            }
            dont_route @ DontRoute => {
                self.options.write().dont_route = *dont_route.get().unwrap();
                return Ok(());
            }
            reuse_port @ ReusePort => {
                let inner = self.inner.read();
                let enabled = *reuse_port.get().unwrap();
                self.options.write().socket.set_reuse_port(enabled);
                if let Inner::Bound(bound) = &*inner { bound.bound_port().set_reuse_port(enabled); }
                return Ok(());
            }
            _ => (),
        });

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
        if let Inner::Bound(bound) = &*inner {
            bound.set_receive_errors(options.ip.recverr());
            bound.set_hop_limit(options.ip.ttl().get());
        }

        let poll = need_iface_poll.then(|| ()).is_some();

        drop(inner);
        drop(options);

        if poll {
            for iface in iter_all_ifaces() { iface.poll(); }
        }

        Ok(())
    }

    fn common(&self) -> &FileCommon {
        &self.common
    }
}

fn network_error_errno(origin: UdpErrorOrigin) -> Errno {
    match origin {
        UdpErrorOrigin::Icmp { type_: 3, code, .. } => match code {
            0 | 6 | 9 | 11 => Errno::ENETUNREACH,
            1 | 10 | 12 | 13 | 14 | 15 => Errno::EHOSTUNREACH,
            2 => Errno::ENOPROTOOPT,
            3 => Errno::ECONNREFUSED,
            4 => Errno::EMSGSIZE,
            5 => Errno::EOPNOTSUPP,
            7 => Errno::EHOSTDOWN,
            8 => Errno::ENONET,
            _ => Errno::EHOSTUNREACH,
        },
        UdpErrorOrigin::Icmp { type_: 12, .. } => Errno::EPROTO,
        UdpErrorOrigin::Icmp { .. } => Errno::EHOSTUNREACH,
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
