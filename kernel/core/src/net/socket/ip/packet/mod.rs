// SPDX-License-Identifier: MPL-2.0

use core::{sync::atomic::{AtomicU16, Ordering}, time::Duration};
use aster_bigtcp::{iface::{InterfaceType, IpTap}, wire::{IpAddress, IpEndpoint, Ipv4Address}};
use aster_softirq::BottomHalfDisabled;
use super::{common::{get_ephemeral_endpoint_on, icmp_error_errno, map_unspecified_to_localhost}, ioctl::ipv4_ioctl, options::{IpOptionSet, Pktinfo, Recverr, SetIpLevelOption}};
use crate::{
    events::IoEvents,
    fs::file::FileCommon,
    net::{iface::{Iface, iter_all_ifaces}, route::{is_broadcast_endpoint, lookup_output_route, lookup_local_iface}, socket::{
        Socket, new_socket_common,
        ip::IpControlMessage,
        options::{Error as SocketError, SocketMark, SocketOption, Timestamping, macros::{sock_option_mut, sock_option_ref}},
        private::SocketPrivate,
        util::{ControlMessage, MessageHeader, RecvFlags, RecvOutput, SendFlags, SocketAddr,
            options::{GetSocketLevelOption, SetSocketLevelOption, SocketOptionSet, SocketTimeouts, check_current_net_raw, check_current_privileged}},
    }},
    prelude::*,
    process::signal::{PollHandle, Pollable, Pollee},
    util::{MultiRead, MultiWrite, ioctl::RawIoctl, net::SockType},
};

static NEXT_IP_ID: AtomicU16 = AtomicU16::new(0);
static NEXT_PING_ID: AtomicU16 = AtomicU16::new(1);
static PING_IDS: SpinLock<BTreeMap<u16, Vec<PingBinding>>, BottomHalfDisabled> = SpinLock::new(BTreeMap::new());

struct PingBinding {
    tap: Weak<IpPacketTap>,
    local: Ipv4Address,
    reuse: bool,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum IpSocketKind { Raw(u8), Ping }

impl IpSocketKind {
    fn protocol(self) -> u8 { match self { Self::Raw(protocol) => protocol, Self::Ping => 1 } }
    fn socket_type(self) -> SockType { match self { Self::Raw(_) => SockType::SOCK_RAW, Self::Ping => SockType::SOCK_DGRAM } }
}

struct IpPacketState {
    local: Ipv4Address,
    peer: Option<Ipv4Address>,
    ping_id: Option<u16>,
    receive_errors: bool,
    pending_error: Option<Errno>,
    errors: VecDeque<PingError>,
    error_bytes: usize,
    packets: VecDeque<IpPacket>,
    queued_bytes: usize,
    capacity: usize,
}

struct PingError {
    errno: Errno,
    type_: u8,
    code: u8,
    info: u32,
    offender: Ipv4Address,
    destination: Ipv4Address,
    payload: Vec<u8>,
    timestamp: Duration,
    ttl: u8,
    tos: u8,
}

#[derive(Clone)]
struct IpPacket {
    bytes: Vec<u8>,
    source: Ipv4Address,
    timestamp: Duration,
}

struct IpPacketTap {
    kind: IpSocketKind,
    state: SpinLock<IpPacketState, BottomHalfDisabled>,
    pollee: Pollee,
}

impl IpTap for IpPacketTap {
    fn accepts(&self, protocol: u8) -> bool { self.kind.protocol() == protocol }
    fn deliver(&self, _ifindex: u32, packet: &[u8]) {
        if packet.len() < 20 || packet[0] >> 4 != 4 || packet[9] != self.kind.protocol() { return; }
        let source = Ipv4Address::new(packet[12], packet[13], packet[14], packet[15]);
        let destination = Ipv4Address::new(packet[16], packet[17], packet[18], packet[19]);
        let mut state = self.state.lock();
        if !state.local.is_unspecified() && state.local != destination { return; }
        if self.kind == IpSocketKind::Ping {
            let header = usize::from(packet[0] & 15) * 4;
            if packet.len() < header + 8 || internet_checksum(&packet[header..]) != 0 { return; }
            if packet[header] != 0 {
                let Some(error) = parse_ping_error(packet, &state) else { return; };
                if !self.is_ping_recipient(state.ping_id.unwrap(), destination) { return; }
                let hard = error.type_ == 12 || error.type_ == 3 && matches!(error.code, 2 | 3 | 4 | 6 | 7 | 8 | 9 | 10 | 13 | 14 | 15);
                if !state.receive_errors && (!hard || state.peer.is_none()) { return; }
                state.pending_error = Some(error.errno);
                if state.receive_errors && state.errors.len() < 64 && state.error_bytes + error.payload.len() <= state.capacity {
                    state.error_bytes += error.payload.len();
                    state.errors.push_back(error);
                }
                drop(state);
                self.pollee.notify(IoEvents::ERR);
                return;
            }
            if packet[header + 1] != 0 || state.ping_id != Some(u16::from_be_bytes([packet[header + 4], packet[header + 5]]))
                || !self.is_ping_recipient(state.ping_id.unwrap(), destination)
            { return; }
        } else if state.peer.is_some_and(|peer| peer != source) { return; }
        if state.queued_bytes + packet.len() > state.capacity { return; }
        state.queued_bytes += packet.len();
        state.packets.push_back(IpPacket {
            bytes: packet.to_vec(), source, timestamp: aster_time::read_wall_time(),
        });
        drop(state);
        self.pollee.notify(IoEvents::IN);
    }
}

impl IpPacketTap {
    fn is_ping_recipient(&self, id: u16, destination: Ipv4Address) -> bool {
        PING_IDS.lock().get(&id).and_then(|bindings| bindings.iter().rev().find(|binding|
            (binding.local.is_unspecified() || binding.local == destination) && binding.tap.strong_count() != 0))
            .is_some_and(|binding| core::ptr::eq(binding.tap.as_ptr(), self))
    }
}

struct Options { socket: SocketOptionSet, ip: IpOptionSet, mark: u32 }

pub(crate) struct IpPacketSocket {
    tap: Arc<IpPacketTap>,
    registered: Vec<Arc<Iface>>,
    options: RwLock<Options>,
    timeouts: SocketTimeouts,
    pollee: Pollee,
    common: FileCommon,
}

impl IpPacketSocket {
    pub(crate) fn create_raw(is_nonblocking: bool, protocol: i32) -> Result<Arc<Self>> {
        check_current_net_raw()?;
        let protocol = u8::try_from(protocol).map_err(|_| Errno::EPROTONOSUPPORT)?;
        if protocol == 0 || protocol == 255 {
            return_errno_with_message!(Errno::EPROTONOSUPPORT, "unsupported raw IP protocol");
        }
        Ok(Self::new(is_nonblocking, IpSocketKind::Raw(protocol)))
    }

    pub(crate) fn create_ping(is_nonblocking: bool) -> Result<Arc<Self>> {
        super::ping_group::check_ping_group()?;
        Ok(Self::new(is_nonblocking, IpSocketKind::Ping))
    }

    fn new(is_nonblocking: bool, kind: IpSocketKind) -> Arc<Self> {
        let pollee = Pollee::new();
        let mut socket_options = SocketOptionSet::new_packet();
        if kind == IpSocketKind::Ping { socket_options.set_reuse_addr(true); }
        let tap = Arc::new(IpPacketTap { kind, pollee: pollee.clone(), state: SpinLock::new(IpPacketState {
            local: Ipv4Address::UNSPECIFIED, peer: None, ping_id: None, receive_errors: false, pending_error: None,
            errors: VecDeque::new(), error_bytes: 0, packets: VecDeque::new(), queued_bytes: 0, capacity: socket_options.recv_buf() as usize,
        }) });
        let registered: Vec<_> = iter_all_ifaces().cloned().collect();
        let observer: Arc<dyn IpTap> = tap.clone();
        for iface in &registered { iface.add_ip_tap(observer.clone()); }
        Arc::new(Self { tap, registered, options: RwLock::new(Options {
            socket: socket_options, ip: IpOptionSet::new_udp(), mark: 0,
        }), timeouts: SocketTimeouts::new(), pollee, common: new_socket_common(is_nonblocking) })
    }

    fn assign_ping_id(&self, requested: u16, bind_address: Option<Ipv4Address>) -> Result<u16> {
        let reuse = self.options.read().socket.reuse_addr();
        let mut state = self.tap.state.lock();
        if let Some(id) = state.ping_id {
            if bind_address.is_none() { return Ok(id); }
            return_errno_with_message!(Errno::EINVAL, "ping socket is already bound");
        }
        let local = bind_address.unwrap_or(state.local);
        let mut ids = PING_IDS.lock();
        let id = if requested != 0 {
            if ids.get(&requested).is_some_and(|bindings| !reuse || bindings.iter().any(|binding| !binding.reuse)) {
                return_errno_with_message!(Errno::EADDRINUSE, "ping identifier is in use");
            }
            requested
        } else {
            let start = NEXT_PING_ID.fetch_add(1, Ordering::Relaxed).max(1);
            let mut id = start;
            loop {
                if !ids.contains_key(&id) { break id; }
                id = if id == u16::MAX { 1 } else { id + 1 };
                if id == start { return_errno_with_message!(Errno::EAGAIN, "no ping identifier is available"); }
            }
        };
        ids.entry(id).or_default().push(PingBinding { tap: Arc::downgrade(&self.tap), local, reuse });
        state.local = local;
        state.ping_id = Some(id);
        Ok(id)
    }

    fn take_pending_error(&self) -> Option<Errno> {
        let error = self.tap.state.lock().pending_error.take();
        if error.is_some() { self.pollee.invalidate(); }
        error
    }

    fn recv_error_queue(&self, writer: &mut dyn MultiWrite, flags: RecvFlags) -> Result<(RecvOutput, MessageHeader)> {
        let mut state = self.tap.state.lock();
        let error = state.errors.pop_front().ok_or_else(|| Error::from(Errno::EAGAIN))?;
        state.error_bytes -= error.payload.len();
        state.pending_error = state.errors.front().map(|next| next.errno);
        drop(state);
        self.pollee.invalidate();
        let copied = writer.write(&mut VmReader::from(error.payload.as_slice())).map_err(|(err, _)| err)?;
        let options = self.options.read();
        let mut controls = Vec::new();
        if options.ip.recvttl() { controls.push(ControlMessage::Ip(IpControlMessage::TimeToLive(error.ttl))); }
        if options.ip.recvtos() { controls.push(ControlMessage::Ip(IpControlMessage::TypeOfService(error.tos))); }
        if options.socket.recv_timestamp_ns() {
            controls.push(ControlMessage::Ip(IpControlMessage::TimestampNs(error.timestamp)));
        } else if options.socket.recv_timestamp() {
            controls.push(ControlMessage::Ip(IpControlMessage::Timestamp(error.timestamp)));
        }
        controls.push(ControlMessage::Ip(IpControlMessage::NetworkError {
            errno: error.errno as u32, origin: 2, type_: error.type_, code: error.code, info: error.info,
            offender: Some(error.offender.octets()),
        }));
        Ok((RecvOutput::new_for_error_queue(flags, copied, error.payload.len()),
            MessageHeader::new(Some(SocketAddr::IPv4(error.destination, 0)), controls)))
    }

    fn try_recv(&self, writer: &mut dyn MultiWrite, flags: RecvFlags) -> Result<(RecvOutput, MessageHeader)> {
        if let Some(error) = self.take_pending_error() { return Err(error.into()); }
        let mut state = self.tap.state.lock();
        let packet = if flags.receive_behavior().will_consume_data() {
            let packet = state.packets.pop_front().ok_or_else(|| Error::from(Errno::EAGAIN))?;
            state.queued_bytes -= packet.bytes.len();
            packet
        } else {
            state.packets.front().cloned().ok_or_else(|| Error::from(Errno::EAGAIN))?
        };
        drop(state);
        self.pollee.invalidate();
        let offset = if self.tap.kind == IpSocketKind::Ping { usize::from(packet.bytes[0] & 15) * 4 } else { 0 };
        let copied = writer.write(&mut VmReader::from(&packet.bytes[offset..])).map_err(|(err, _)| err)?;
        let options = self.options.read();
        let mut controls = Vec::new();
        if options.ip.recvttl() { controls.push(ControlMessage::Ip(IpControlMessage::TimeToLive(packet.bytes[8]))); }
        if options.ip.recvtos() { controls.push(ControlMessage::Ip(IpControlMessage::TypeOfService(packet.bytes[1]))); }
        if options.socket.recv_timestamp_ns() {
            controls.push(ControlMessage::Ip(IpControlMessage::TimestampNs(packet.timestamp)));
        } else if options.socket.recv_timestamp() {
            controls.push(ControlMessage::Ip(IpControlMessage::Timestamp(packet.timestamp)));
        }
        Ok((RecvOutput::new_for_packet(flags, copied, packet.bytes.len() - offset),
            MessageHeader::new(Some(SocketAddr::IPv4(packet.source, 0)), controls)))
    }
}

impl SocketPrivate for IpPacketSocket {
    fn is_nonblocking(&self) -> bool { self.common.is_nonblocking() }
    fn protocol_ioctl(&self, ioctl: RawIoctl) -> Result<i32> { ipv4_ioctl(ioctl) }
}

impl Pollable for IpPacketSocket {
    fn poll(&self, mask: IoEvents, poller: Option<&mut PollHandle>) -> IoEvents {
        self.pollee.poll_with(mask, poller, || {
            let state = self.tap.state.lock();
            let mut events = IoEvents::OUT;
            if !state.packets.is_empty() { events |= IoEvents::IN; }
            if state.pending_error.is_some() || !state.errors.is_empty() { events |= IoEvents::ERR; }
            events
        })
    }
}

impl Socket for IpPacketSocket {
    fn bind(&self, address: SocketAddr) -> Result<()> {
        let SocketAddr::IPv4(address, port) = address else { return_errno_with_message!(Errno::EAFNOSUPPORT, "expected an IPv4 address"); };
        if self.tap.kind == IpSocketKind::Ping && is_broadcast_endpoint(&IpEndpoint::new(address.into(), port)) {
            return_errno_with_message!(Errno::EADDRNOTAVAIL, "ping socket cannot bind a broadcast address");
        }
        if !address.is_unspecified() { lookup_local_iface(IpAddress::Ipv4(address))?; }
        if self.tap.kind == IpSocketKind::Ping {
            self.assign_ping_id(port, Some(address))?;
        } else {
            let mut state = self.tap.state.lock();
            if state.peer.is_some() { return_errno_with_message!(Errno::EINVAL, "connected raw socket cannot bind"); }
            state.local = address;
        }
        Ok(())
    }

    fn connect(&self, address: SocketAddr) -> Result<()> {
        let endpoint: IpEndpoint = map_unspecified_to_localhost(address.try_into()?);
        let IpAddress::Ipv4(peer) = endpoint.addr else { return_errno_with_message!(Errno::EAFNOSUPPORT, "expected an IPv4 address"); };
        let mark = self.options.read().mark;
        let (iface, _, _) = lookup_output_route(endpoint.addr, mark, false, None)?;
        if is_broadcast_endpoint(&endpoint) && !self.options.read().socket.broadcast() {
            return_errno_with_message!(Errno::EACCES, "broadcast requires SO_BROADCAST");
        }
        let local = self.tap.state.lock().local;
        if local.is_loopback() && iface.type_() != InterfaceType::LOOPBACK {
            return_errno_with_message!(Errno::EINVAL, "loopback source requires a loopback route");
        }
        let source = get_ephemeral_endpoint_on(&iface, &endpoint)?.addr;
        if self.tap.kind == IpSocketKind::Ping { self.assign_ping_id(0, None)?; }
        let mut state = self.tap.state.lock();
        if state.local.is_loopback() && iface.type_() != InterfaceType::LOOPBACK {
            return_errno_with_message!(Errno::EINVAL, "loopback source requires a loopback route");
        }
        if state.local.is_unspecified() && let IpAddress::Ipv4(source) = source {
            state.local = source;
            if let Some(id) = state.ping_id
                && let Some(bindings) = PING_IDS.lock().get_mut(&id)
                && let Some(binding) = bindings.iter_mut().find(|binding| core::ptr::eq(binding.tap.as_ptr(), Arc::as_ptr(&self.tap)))
            { binding.local = source; }
        }
        state.peer = Some(peer);
        Ok(())
    }

    fn addr(&self) -> Result<SocketAddr> {
        let state = self.tap.state.lock();
        Ok(SocketAddr::IPv4(state.local, state.ping_id.unwrap_or(0)))
    }
    fn peer_addr(&self) -> Result<SocketAddr> {
        let peer = self.tap.state.lock().peer.ok_or_else(|| Error::from(Errno::ENOTCONN))?;
        Ok(SocketAddr::IPv4(peer, 0))
    }

    fn sendmsg(&self, reader: &mut dyn MultiRead, message: MessageHeader, flags: SendFlags) -> Result<usize> {
        if let Some(error) = self.take_pending_error() { return Err(error.into()); }
        if flags.bits() & !(SendFlags::MSG_DONTWAIT | SendFlags::MSG_NOSIGNAL).bits() != 0 {
            return_errno_with_message!(Errno::EOPNOTSUPP, "unsupported raw IPv4 send flags");
        }
        if !message.control_messages.is_empty() { return_errno_with_message!(Errno::EOPNOTSUPP, "raw IP control messages are not supported"); }
        let destination = match message.addr {
            Some(SocketAddr::IPv4(address, _)) => address,
            Some(_) => return_errno_with_message!(Errno::EAFNOSUPPORT, "expected an IPv4 address"),
            None => self.tap.state.lock().peer.ok_or_else(|| Error::from(Errno::EDESTADDRREQ))?,
        };
        let endpoint = map_unspecified_to_localhost(IpEndpoint::new(destination.into(), 0));
        let mark = self.options.read().mark;
        let (iface, next_hop, route) = lookup_output_route(endpoint.addr, mark, false, None)?;
        if is_broadcast_endpoint(&endpoint) && !self.options.read().socket.broadcast() {
            return_errno_with_message!(Errno::EACCES, "broadcast requires SO_BROADCAST");
        }
        let local = self.tap.state.lock().local;
        if local.is_loopback() && iface.type_() != InterfaceType::LOOPBACK {
            return_errno_with_message!(Errno::EINVAL, "loopback source requires a loopback route");
        }
        let source = if local.is_unspecified() { get_ephemeral_endpoint_on(&iface, &endpoint)?.addr } else { local.into() };
        let IpAddress::Ipv4(source) = source else { return_errno_with_message!(Errno::EAFNOSUPPORT, "expected an IPv4 source"); };
        let IpAddress::Ipv4(destination) = endpoint.addr else { return_errno_with_message!(Errno::EAFNOSUPPORT, "expected an IPv4 destination"); };
        let ping_id = if self.tap.kind == IpSocketKind::Ping { Some(self.assign_ping_id(0, None)?) } else { None };
        let size = reader.sum_lens();
        if size > u16::MAX as usize - 20 { return_errno_with_message!(Errno::EMSGSIZE, "raw IPv4 datagram is too large"); }
        let mut packet = vec![0u8; size + 20];
        let copied = reader.read(&mut VmWriter::from(&mut packet[20..])).map_err(|(err, _)| err)?;
        packet.truncate(copied + 20);
        if let Some(id) = ping_id {
            if copied < 8 || packet[20] != 8 || packet[21] != 0 {
                return_errno_with_message!(Errno::EINVAL, "ping datagrams must be ICMP echo requests");
            }
            packet[22..24].fill(0);
            packet[24..26].copy_from_slice(&id.to_be_bytes());
            let checksum = internet_checksum(&packet[20..]);
            packet[22..24].copy_from_slice(&checksum.to_be_bytes());
        }
        let options = self.options.read();
        packet[0] = 0x45; packet[1] = options.ip.tos(); packet[2..4].copy_from_slice(&((copied + 20) as u16).to_be_bytes());
        let path = iface.path_mtu_for_route(endpoint.addr, route);
        let dont_fragment = !path.locked && copied + 20 <= path.mtu;
        let id = if dont_fragment { 0 } else { NEXT_IP_ID.fetch_add(1, Ordering::Relaxed) };
        packet[4..6].copy_from_slice(&id.to_be_bytes());
        if dont_fragment { packet[6] = 0x40; }
        packet[8] = options.ip.ttl().get(); packet[9] = self.tap.kind.protocol();
        packet[12..16].copy_from_slice(&source.octets()); packet[16..20].copy_from_slice(&destination.octets());
        let checksum = internet_checksum(&packet[..20]); packet[10..12].copy_from_slice(&checksum.to_be_bytes());
        drop(options);
        iface.send_ipv4_packet(&packet, path.mtu, next_hop).map_err(|error| Error::with_message(match error {
            aster_bigtcp::errors::LinkSendError::Down => Errno::ENETDOWN,
            aster_bigtcp::errors::LinkSendError::TooLong => Errno::EMSGSIZE,
            aster_bigtcp::errors::LinkSendError::Busy | aster_bigtcp::errors::LinkSendError::NoMemory => Errno::ENOBUFS,
            _ => Errno::EINVAL,
        }, "cannot enqueue raw IPv4 packet"))?;
        iface.poll();
        Ok(copied)
    }

    fn recvmsg(&self, writer: &mut dyn MultiWrite, flags: RecvFlags) -> Result<(RecvOutput, MessageHeader)> {
        if flags.contains(RecvFlags::MSG_ERRQUEUE) { return self.recv_error_queue(writer, flags); }
        if flags.bits() & !(RecvFlags::MSG_DONTWAIT | RecvFlags::MSG_PEEK | RecvFlags::MSG_TRUNC | RecvFlags::MSG_CMSG_CLOEXEC).bits() != 0 {
            return_errno_with_message!(Errno::EOPNOTSUPP, "unsupported raw IPv4 receive flags");
        }
        if flags.contains(RecvFlags::MSG_DONTWAIT) { self.try_recv(writer, flags) }
        else { self.block_on(IoEvents::IN, self.timeouts.recv_timeout(), || self.try_recv(writer, flags)) }
    }

    fn get_option(&self, option: &mut dyn SocketOption) -> Result<()> {
        sock_option_mut!(match option {
            error @ SocketError => { error.set(self.take_pending_error().map(Error::from)); return Ok(()); }
            mark @ SocketMark => { mark.set(self.options.read().mark); return Ok(()); }
            _ => (),
        });
        let options = self.options.read();
        let level = IpSocketLevel(&self.timeouts, self.tap.kind.socket_type());
        match options.socket.get_option(option, &level) {
            Err(err) if err.error() == Errno::ENOPROTOOPT => options.ip.get_option(option),
            result => result,
        }
    }

    fn set_option(&self, option: &dyn SocketOption) -> Result<()> {
        sock_option_ref!(match option {
            mark @ SocketMark => {
                check_current_net_raw().or_else(|_| check_current_privileged())?;
                self.options.write().mark = *mark.get().unwrap();
                return Ok(());
            }
            pktinfo @ Pktinfo => {
                if *pktinfo.get().unwrap() { return_errno_with_message!(Errno::ENOPROTOOPT, "raw IPv4 packet information is not supported"); }
            }
            recverr @ Recverr => {
                if *recverr.get().unwrap() && self.tap.kind != IpSocketKind::Ping { return_errno_with_message!(Errno::ENOPROTOOPT, "raw IPv4 error queues are not supported"); }
            }
            timestamping @ Timestamping => {
                if *timestamping.get().unwrap() != 0 { return_errno_with_message!(Errno::ENOPROTOOPT, "raw IPv4 timestamping is not supported"); }
            }
            _ => (),
        });
        let mut options = self.options.write();
        let level = IpSocketLevel(&self.timeouts, self.tap.kind.socket_type());
        match options.socket.set_option(option, &level) {
            Err(err) if err.error() == Errno::ENOPROTOOPT => { options.ip.set_option(option, self)?; }
            Err(err) => return Err(err),
            Ok(_) => (),
        }
        let mut state = self.tap.state.lock();
        state.capacity = options.socket.recv_buf() as usize;
        if let Some(id) = state.ping_id
            && let Some(bindings) = PING_IDS.lock().get_mut(&id)
            && let Some(binding) = bindings.iter_mut().find(|binding| core::ptr::eq(binding.tap.as_ptr(), Arc::as_ptr(&self.tap)))
        { binding.reuse = options.socket.reuse_addr(); }
        state.receive_errors = options.ip.recverr();
        if !state.receive_errors { state.errors.clear(); state.error_bytes = 0; }
        Ok(())
    }
    fn common(&self) -> &FileCommon { &self.common }
}

impl SetIpLevelOption for IpPacketSocket {
    fn set_hdrincl(&self, hdrincl: bool) -> Result<()> {
        if hdrincl { return_errno_with_message!(Errno::ENOPROTOOPT, "raw IPv4 header inclusion is not supported"); }
        Ok(())
    }
}

struct IpSocketLevel<'a>(&'a SocketTimeouts, SockType);
impl GetSocketLevelOption for IpSocketLevel<'_> {
    fn socket_type(&self) -> SockType { self.1 }
    fn is_listening(&self) -> bool { false }
    fn socket_timeouts(&self) -> Option<&SocketTimeouts> { Some(self.0) }
}
impl SetSocketLevelOption for IpSocketLevel<'_> {
    fn socket_timeouts(&self) -> Option<&SocketTimeouts> { Some(self.0) }
}

impl Drop for IpPacketSocket {
    fn drop(&mut self) {
        let tap: Arc<dyn IpTap> = self.tap.clone();
        for iface in &self.registered { iface.remove_ip_tap(&tap); }
        if let Some(id) = self.tap.state.lock().ping_id {
            let mut ids = PING_IDS.lock();
            if let Some(bindings) = ids.get_mut(&id) {
                bindings.retain(|binding| !core::ptr::eq(binding.tap.as_ptr(), Arc::as_ptr(&self.tap)));
                if bindings.is_empty() { ids.remove(&id); }
            }
        }
    }
}

fn parse_ping_error(packet: &[u8], state: &IpPacketState) -> Option<PingError> {
    let header = usize::from(packet[0] & 15) * 4;
    let icmp = packet.get(header..)?;
    if !matches!((icmp[0], icmp[1]), (3, 0..=15) | (11, 0) | (12, _)) { return None; }
    let quoted = icmp.get(8..)?;
    if quoted.len() < 28 || quoted[0] >> 4 != 4 || quoted[9] != 1 { return None; }
    let inner_header = usize::from(quoted[0] & 15) * 4;
    if inner_header < 20 || quoted.len() < inner_header + 8 || quoted[inner_header] != 8 || quoted[inner_header + 1] != 0 { return None; }
    let id = u16::from_be_bytes([quoted[inner_header + 4], quoted[inner_header + 5]]);
    if state.ping_id != Some(id) || quoted[12..16] != packet[16..20] { return None; }
    let destination = Ipv4Address::new(quoted[16], quoted[17], quoted[18], quoted[19]);
    let total = usize::from(u16::from_be_bytes([quoted[2], quoted[3]]));
    if total < inner_header + 8 { return None; }
    let end = total.min(quoted.len());
    Some(PingError {
        errno: icmp_error_errno(icmp[0], icmp[1]), type_: icmp[0], code: icmp[1],
        info: match (icmp[0], icmp[1]) { (3, 4) => u32::from(u16::from_be_bytes([icmp[6], icmp[7]])), (12, _) => u32::from(icmp[4]), _ => 0 },
        offender: Ipv4Address::new(packet[12], packet[13], packet[14], packet[15]), destination,
        payload: quoted[inner_header..end].to_vec(), timestamp: aster_time::read_wall_time(), ttl: packet[8], tos: packet[1],
    })
}

fn internet_checksum(bytes: &[u8]) -> u16 {
    let mut sum = 0u32;
    let mut pairs = bytes.chunks_exact(2);
    for pair in &mut pairs { sum += u32::from(u16::from_be_bytes([pair[0], pair[1]])); }
    if let Some(byte) = pairs.remainder().first() { sum += u32::from(*byte) << 8; }
    while sum >> 16 != 0 { sum = (sum & 0xffff) + (sum >> 16); }
    !(sum as u16)
}
