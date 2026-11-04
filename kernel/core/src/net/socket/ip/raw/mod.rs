// SPDX-License-Identifier: MPL-2.0

use core::{sync::atomic::{AtomicU16, Ordering}, time::Duration};
use aster_bigtcp::{iface::IpTap, wire::{IpAddress, IpEndpoint, Ipv4Address}};
use aster_softirq::BottomHalfDisabled;
use super::{common::{get_ephemeral_endpoint_on, map_unspecified_to_localhost}, ioctl::ipv4_ioctl, options::{IpOptionSet, Pktinfo, Recverr, SetIpLevelOption}};
use crate::{
    events::IoEvents,
    fs::file::FileCommon,
    net::{iface::{Iface, iter_all_ifaces}, route::{is_broadcast_endpoint, lookup_iface, lookup_local_iface}, socket::{
        Socket, new_socket_common,
        ip::IpControlMessage,
        options::{Error as SocketError, SocketOption, Timestamping, macros::{sock_option_mut, sock_option_ref}},
        private::SocketPrivate,
        util::{ControlMessage, MessageHeader, RecvFlags, RecvOutput, SendFlags, SocketAddr,
            options::{GetSocketLevelOption, SetSocketLevelOption, SocketOptionSet, SocketTimeouts, check_current_net_raw}},
    }},
    prelude::*,
    process::signal::{PollHandle, Pollable, Pollee},
    util::{MultiRead, MultiWrite, ioctl::RawIoctl, net::SockType},
};

static NEXT_IP_ID: AtomicU16 = AtomicU16::new(0);

struct RawState {
    local: Ipv4Address,
    peer: Option<Ipv4Address>,
    packets: VecDeque<RawPacket>,
    queued_bytes: usize,
    capacity: usize,
}

#[derive(Clone)]
struct RawPacket {
    bytes: Vec<u8>,
    source: Ipv4Address,
    timestamp: Duration,
}

struct RawTap {
    protocol: u8,
    state: SpinLock<RawState, BottomHalfDisabled>,
    pollee: Pollee,
}

impl IpTap for RawTap {
    fn accepts(&self, protocol: u8) -> bool { self.protocol == protocol }
    fn deliver(&self, _ifindex: u32, packet: &[u8]) {
        if packet.len() < 20 || packet[0] >> 4 != 4 || packet[9] != self.protocol { return; }
        let source = Ipv4Address::new(packet[12], packet[13], packet[14], packet[15]);
        let destination = Ipv4Address::new(packet[16], packet[17], packet[18], packet[19]);
        let mut state = self.state.lock();
        if !state.local.is_unspecified() && state.local != destination || state.peer.is_some_and(|peer| peer != source)
            || state.queued_bytes + packet.len() > state.capacity
        { return; }
        state.queued_bytes += packet.len();
        state.packets.push_back(RawPacket {
            bytes: packet.to_vec(), source, timestamp: aster_time::read_wall_time(),
        });
        drop(state);
        self.pollee.notify(IoEvents::IN);
    }
}

struct Options { socket: SocketOptionSet, ip: IpOptionSet }

pub(crate) struct RawIpSocket {
    tap: Arc<RawTap>,
    registered: Vec<Arc<Iface>>,
    options: RwLock<Options>,
    timeouts: SocketTimeouts,
    pollee: Pollee,
    common: FileCommon,
}

impl RawIpSocket {
    pub(crate) fn create(is_nonblocking: bool, protocol: i32) -> Result<Arc<Self>> {
        check_current_net_raw()?;
        let protocol = u8::try_from(protocol).map_err(|_| Errno::EPROTONOSUPPORT)?;
        if protocol == 0 || protocol == 255 {
            return_errno_with_message!(Errno::EPROTONOSUPPORT, "unsupported raw IP protocol");
        }
        let pollee = Pollee::new();
        let socket_options = SocketOptionSet::new_packet();
        let tap = Arc::new(RawTap { protocol, pollee: pollee.clone(), state: SpinLock::new(RawState {
            local: Ipv4Address::UNSPECIFIED, peer: None, packets: VecDeque::new(), queued_bytes: 0, capacity: socket_options.recv_buf() as usize,
        }) });
        let registered: Vec<_> = iter_all_ifaces().cloned().collect();
        let observer: Arc<dyn IpTap> = tap.clone();
        for iface in &registered { iface.add_ip_tap(observer.clone()); }
        Ok(Arc::new(Self { tap, registered, options: RwLock::new(Options {
            socket: socket_options, ip: IpOptionSet::new_udp(),
        }), timeouts: SocketTimeouts::new(), pollee, common: new_socket_common(is_nonblocking) }))
    }

    fn try_recv(&self, writer: &mut dyn MultiWrite, flags: RecvFlags) -> Result<(RecvOutput, MessageHeader)> {
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
        let copied = writer.write(&mut VmReader::from(packet.bytes.as_slice())).map_err(|(err, _)| err)?;
        let options = self.options.read();
        let mut controls = Vec::new();
        if options.ip.recvttl() { controls.push(ControlMessage::Ip(IpControlMessage::TimeToLive(packet.bytes[8]))); }
        if options.ip.recvtos() { controls.push(ControlMessage::Ip(IpControlMessage::TypeOfService(packet.bytes[1]))); }
        if options.socket.recv_timestamp_ns() {
            controls.push(ControlMessage::Ip(IpControlMessage::TimestampNs(packet.timestamp)));
        } else if options.socket.recv_timestamp() {
            controls.push(ControlMessage::Ip(IpControlMessage::Timestamp(packet.timestamp)));
        }
        Ok((RecvOutput::new_for_packet(flags, copied, packet.bytes.len()),
            MessageHeader::new(Some(SocketAddr::IPv4(packet.source, 0)), controls)))
    }
}

impl SocketPrivate for RawIpSocket {
    fn is_nonblocking(&self) -> bool { self.common.is_nonblocking() }
    fn protocol_ioctl(&self, ioctl: RawIoctl) -> Result<i32> { ipv4_ioctl(ioctl) }
}

impl Pollable for RawIpSocket {
    fn poll(&self, mask: IoEvents, poller: Option<&mut PollHandle>) -> IoEvents {
        self.pollee.poll_with(mask, poller, || {
            let state = self.tap.state.lock();
            if state.packets.is_empty() { IoEvents::OUT } else { IoEvents::OUT | IoEvents::IN }
        })
    }
}

impl Socket for RawIpSocket {
    fn bind(&self, address: SocketAddr) -> Result<()> {
        let SocketAddr::IPv4(address, _) = address else { return_errno_with_message!(Errno::EAFNOSUPPORT, "expected an IPv4 address"); };
        if !address.is_unspecified() { lookup_local_iface(IpAddress::Ipv4(address))?; }
        self.tap.state.lock().local = address;
        Ok(())
    }

    fn connect(&self, address: SocketAddr) -> Result<()> {
        let endpoint: IpEndpoint = map_unspecified_to_localhost(address.try_into()?);
        let IpAddress::Ipv4(peer) = endpoint.addr else { return_errno_with_message!(Errno::EAFNOSUPPORT, "expected an IPv4 address"); };
        let iface = lookup_iface(endpoint.addr)?;
        if is_broadcast_endpoint(&endpoint) && !self.options.read().socket.broadcast() {
            return_errno_with_message!(Errno::EACCES, "broadcast requires SO_BROADCAST");
        }
        let source = get_ephemeral_endpoint_on(&iface, &endpoint)?.addr;
        let mut state = self.tap.state.lock();
        if state.local.is_unspecified() && let IpAddress::Ipv4(source) = source { state.local = source; }
        state.peer = Some(peer);
        Ok(())
    }

    fn addr(&self) -> Result<SocketAddr> { Ok(SocketAddr::IPv4(self.tap.state.lock().local, 0)) }
    fn peer_addr(&self) -> Result<SocketAddr> {
        let peer = self.tap.state.lock().peer.ok_or_else(|| Error::from(Errno::ENOTCONN))?;
        Ok(SocketAddr::IPv4(peer, 0))
    }

    fn sendmsg(&self, reader: &mut dyn MultiRead, message: MessageHeader, flags: SendFlags) -> Result<usize> {
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
        let iface = lookup_iface(endpoint.addr)?;
        if is_broadcast_endpoint(&endpoint) && !self.options.read().socket.broadcast() {
            return_errno_with_message!(Errno::EACCES, "broadcast requires SO_BROADCAST");
        }
        let local = self.tap.state.lock().local;
        let source = if local.is_unspecified() { get_ephemeral_endpoint_on(&iface, &endpoint)?.addr } else { local.into() };
        let IpAddress::Ipv4(source) = source else { return_errno_with_message!(Errno::EAFNOSUPPORT, "expected an IPv4 source"); };
        let IpAddress::Ipv4(destination) = endpoint.addr else { return_errno_with_message!(Errno::EAFNOSUPPORT, "expected an IPv4 destination"); };
        let size = reader.sum_lens();
        if size > u16::MAX as usize - 20 { return_errno_with_message!(Errno::EMSGSIZE, "raw IPv4 datagram is too large"); }
        let mut packet = vec![0u8; size + 20];
        let copied = reader.read(&mut VmWriter::from(&mut packet[20..])).map_err(|(err, _)| err)?;
        packet.truncate(copied + 20);
        let options = self.options.read();
        packet[0] = 0x45; packet[1] = options.ip.tos(); packet[2..4].copy_from_slice(&((copied + 20) as u16).to_be_bytes());
        let path = iface.path_mtu(endpoint.addr);
        let dont_fragment = !path.locked && copied + 20 <= path.mtu;
        let id = if dont_fragment { 0 } else { NEXT_IP_ID.fetch_add(1, Ordering::Relaxed) };
        packet[4..6].copy_from_slice(&id.to_be_bytes());
        if dont_fragment { packet[6] = 0x40; }
        packet[8] = options.ip.ttl().get(); packet[9] = self.tap.protocol;
        packet[12..16].copy_from_slice(&source.octets()); packet[16..20].copy_from_slice(&destination.octets());
        let checksum = ipv4_checksum(&packet[..20]); packet[10..12].copy_from_slice(&checksum.to_be_bytes());
        drop(options);
        iface.send_ipv4_packet(&packet, path.mtu).map_err(|error| Error::with_message(match error {
            aster_bigtcp::errors::LinkSendError::Down => Errno::ENETDOWN,
            aster_bigtcp::errors::LinkSendError::TooLong => Errno::EMSGSIZE,
            aster_bigtcp::errors::LinkSendError::Busy | aster_bigtcp::errors::LinkSendError::NoMemory => Errno::ENOBUFS,
            _ => Errno::EINVAL,
        }, "cannot enqueue raw IPv4 packet"))?;
        iface.poll();
        Ok(copied)
    }

    fn recvmsg(&self, writer: &mut dyn MultiWrite, flags: RecvFlags) -> Result<(RecvOutput, MessageHeader)> {
        if flags.contains(RecvFlags::MSG_ERRQUEUE) { return_errno_with_message!(Errno::EAGAIN, "raw IPv4 error queue is empty"); }
        if flags.bits() & !(RecvFlags::MSG_DONTWAIT | RecvFlags::MSG_PEEK | RecvFlags::MSG_TRUNC | RecvFlags::MSG_CMSG_CLOEXEC).bits() != 0 {
            return_errno_with_message!(Errno::EOPNOTSUPP, "unsupported raw IPv4 receive flags");
        }
        if flags.contains(RecvFlags::MSG_DONTWAIT) { self.try_recv(writer, flags) }
        else { self.block_on(IoEvents::IN, self.timeouts.recv_timeout(), || self.try_recv(writer, flags)) }
    }

    fn get_option(&self, option: &mut dyn SocketOption) -> Result<()> {
        sock_option_mut!(match option { error @ SocketError => { error.set(None); return Ok(()); } _ => (), });
        let options = self.options.read();
        let level = RawSocketLevel(&self.timeouts);
        match options.socket.get_option(option, &level) {
            Err(err) if err.error() == Errno::ENOPROTOOPT => options.ip.get_option(option),
            result => result,
        }
    }

    fn set_option(&self, option: &dyn SocketOption) -> Result<()> {
        sock_option_ref!(match option {
            pktinfo @ Pktinfo => {
                if *pktinfo.get().unwrap() { return_errno_with_message!(Errno::ENOPROTOOPT, "raw IPv4 packet information is not supported"); }
            }
            recverr @ Recverr => {
                if *recverr.get().unwrap() { return_errno_with_message!(Errno::ENOPROTOOPT, "raw IPv4 error queues are not supported"); }
            }
            timestamping @ Timestamping => {
                if *timestamping.get().unwrap() != 0 { return_errno_with_message!(Errno::ENOPROTOOPT, "raw IPv4 timestamping is not supported"); }
            }
            _ => (),
        });
        let mut options = self.options.write();
        let level = RawSocketLevel(&self.timeouts);
        match options.socket.set_option(option, &level) {
            Err(err) if err.error() == Errno::ENOPROTOOPT => { options.ip.set_option(option, self)?; }
            Err(err) => return Err(err),
            Ok(_) => (),
        }
        self.tap.state.lock().capacity = options.socket.recv_buf() as usize;
        Ok(())
    }
    fn common(&self) -> &FileCommon { &self.common }
}

impl SetIpLevelOption for RawIpSocket {
    fn set_hdrincl(&self, hdrincl: bool) -> Result<()> {
        if hdrincl { return_errno_with_message!(Errno::ENOPROTOOPT, "raw IPv4 header inclusion is not supported"); }
        Ok(())
    }
}

struct RawSocketLevel<'a>(&'a SocketTimeouts);
impl GetSocketLevelOption for RawSocketLevel<'_> {
    fn socket_type(&self) -> SockType { SockType::SOCK_RAW }
    fn is_listening(&self) -> bool { false }
    fn socket_timeouts(&self) -> Option<&SocketTimeouts> { Some(self.0) }
}
impl SetSocketLevelOption for RawSocketLevel<'_> {
    fn socket_timeouts(&self) -> Option<&SocketTimeouts> { Some(self.0) }
}

impl Drop for RawIpSocket {
    fn drop(&mut self) {
        let tap: Arc<dyn IpTap> = self.tap.clone();
        for iface in &self.registered { iface.remove_ip_tap(&tap); }
    }
}

fn ipv4_checksum(bytes: &[u8]) -> u16 {
    let mut sum = 0u32;
    for pair in bytes.chunks_exact(2) { sum += u32::from(u16::from_be_bytes([pair[0], pair[1]])); }
    while sum >> 16 != 0 { sum = (sum & 0xffff) + (sum >> 16); }
    !(sum as u16)
}
