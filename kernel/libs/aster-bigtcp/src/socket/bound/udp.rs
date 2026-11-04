// SPDX-License-Identifier: MPL-2.0

use alloc::{collections::VecDeque, sync::{Arc, Weak}, vec, vec::Vec};
use core::sync::atomic::{AtomicU8, Ordering};

use aster_softirq::BottomHalfDisabled;
use ostd::sync::SpinLock;
use spin::Once;
use smoltcp::{
    iface::Context,
    socket::udp::UdpMetadata,
    storage::{PacketBuffer, PacketMetadata, SliceLike},
    wire::{IpAddress, IpEndpoint, IpProtocol, IpRepr, Ipv4Address, UdpRepr, UDP_HEADER_LEN},
};

use super::ReceiveBehavior;
use crate::{
    errors::udp::SendError,
    ext::Ext,
    iface::{PacketSlice, UdpFailure, UdpReservation},
    socket::{
        event::{SocketEventObserver, SocketEvents},
        unbound::{UDP_METADATA_LEN, UDP_RECV_PAYLOAD_LEN, UDP_SEND_PAYLOAD_LEN},
    },
};

pub struct UdpSocket<E: Ext>(Arc<UdpSocketBg<E>>);

#[derive(Clone, Copy)]
pub enum UdpNextHop {
    Routed,
    Direct,
}

#[derive(Clone, Debug)]
pub struct UdpIpv4Options {
    first_hop: Option<Ipv4Address>,
    bytes: Vec<u8>,
}

impl UdpIpv4Options {
    pub fn new(first_hop: Option<Ipv4Address>, bytes: Vec<u8>) -> Option<Self> {
        if bytes.len() > 40 || bytes.len() % 4 != 0 { return None; }
        Some(Self { first_hop, bytes })
    }
    pub fn first_hop(&self) -> Option<Ipv4Address> { self.first_hop }
    pub(crate) fn bytes(&self) -> &[u8] { &self.bytes }
}

#[derive(Clone, Copy)]
pub enum UdpFragmentation {
    Allow(usize),
    DontFragment,
}

pub(crate) struct UdpSocketBg<E: Ext> {
    bound: UdpReservation<E>,
    inner: UdpSocketInner,
    observer: E::UdpEventObserver,
    open: SpinLock<bool, BottomHalfDisabled>,
}

/// States needed by [`UdpSocketBg`].
struct UdpSocketInner {
    tx: SpinLock<TxQueue, BottomHalfDisabled>,
    ttl: AtomicU8,
    received: SpinLock<PacketBuffer<'static, ReceivedMetadata>, BottomHalfDisabled>,
    tx_stamps: SpinLock<VecDeque<TxTimestamp>, BottomHalfDisabled>,
    errors: SpinLock<UdpErrors, BottomHalfDisabled>,
    failure_reporter: Once<Arc<dyn UdpFailure>>,
}

#[derive(Default)]
struct TxQueue {
    packets: VecDeque<TxDatagram>,
    queued_bytes: usize,
}

struct TxDatagram {
    iface: u32,
    source: IpAddress,
    destination: IpEndpoint,
    ttl: u8,
    tos: u8,
    next_hop: UdpNextHop,
    fragmentation: UdpFragmentation,
    ipv4_options: Option<UdpIpv4Options>,
    tag: u32,
    payload: Vec<u8>,
}

impl TxQueue {
    fn can_enqueue(&self, size: usize) -> bool {
        self.packets.len() < UDP_METADATA_LEN && self.queued_bytes + size <= UDP_SEND_PAYLOAD_LEN
    }

    fn enqueue(&mut self, packet: TxDatagram) -> Result<(), SendError> {
        if !self.can_enqueue(packet.payload.len()) { return Err(SendError::BufferFull); }
        self.queued_bytes += packet.payload.len();
        self.packets.push_back(packet);
        Ok(())
    }

    fn take_for(&mut self, ifindex: u32) -> Option<TxDatagram> {
        let position = self.packets.iter().position(|packet| packet.iface == ifindex)?;
        let packet = self.packets.remove(position).unwrap();
        self.queued_bytes -= packet.payload.len();
        Some(packet)
    }
}

#[derive(Clone, Copy)]
struct ReceivedMetadata {
    udp: UdpMetadata,
    timestamp_ns: u64,
    ttl: u8,
    tos: u8,
    ifindex: u32,
}

struct UdpFailureReporter<E: Ext> {
    socket: Weak<UdpSocketBg<E>>,
}

impl<E: Ext> UdpFailure for UdpFailureReporter<E> {
    fn report(&self, destination: IpEndpoint, offender: IpAddress, payload: Vec<u8>, tos: u8) {
        if let Some(socket) = self.socket.upgrade() {
            socket.report_error(UdpError {
                destination,
                payload,
                origin: UdpErrorOrigin::Icmp { offender, type_: 3, code: 1, info: 0, ttl: 64, tos },
                timestamp_ns: 0,
            });
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub enum UdpErrorOrigin {
    Icmp { offender: IpAddress, type_: u8, code: u8, info: u32, ttl: u8, tos: u8 },
}

impl UdpErrorOrigin {
    fn is_hard(self) -> bool {
        match self {
            Self::Icmp { type_: 12, .. } => true,
            Self::Icmp { type_: 3, code: 2 | 3 | 4 | 6 | 7 | 8 | 9 | 10 | 13 | 14 | 15, .. } => true,
            Self::Icmp { .. } => false,
        }
    }
}

#[derive(Clone, Debug)]
pub struct UdpError {
    pub destination: IpEndpoint,
    pub payload: Vec<u8>,
    pub origin: UdpErrorOrigin,
    pub timestamp_ns: u64,
}

#[derive(Default)]
struct UdpErrors {
    peer: Option<IpEndpoint>,
    recverr: bool,
    ignore_fragmentation_error: bool,
    ignore_path_mtu: bool,
    sent_paths: VecDeque<SentPath>,
    pending: Option<UdpErrorOrigin>,
    queue: VecDeque<UdpError>,
    queued_bytes: usize,
}

struct SentPath {
    source: IpEndpoint,
    destination: IpEndpoint,
    ifindex: u32,
}

/// The time an outgoing packet that asked for a timestamp left the interface.
#[derive(Clone, Copy, Debug)]
pub struct TxTimestamp {
    /// The tag the sender gave the packet.
    pub tag: u32,
    /// The wall-clock time in nanoseconds since the Unix epoch.
    pub wall_time_ns: u64,
}

const MAX_PENDING_TX_STAMPS: usize = 64;

impl<E: Ext> Drop for UdpSocket<E> {
    fn drop(&mut self) {
        let mut open = self.0.open.lock();
        *open = false;
        self.0.bound.release();
        self.0.bound.registry().unregister(&self.0);
    }
}

impl<E: Ext> UdpSocketBg<E> {
    pub(crate) fn can_process(&self, port: u16) -> bool {
        self.bound.endpoint().port == port
    }

    pub(crate) fn same_reuse_port_group(&self, other: &Self) -> bool {
        self.bound.same_reuse_port_group(&other.bound)
    }

    fn notify_events(&self, events: SocketEvents) {
        self.observer.on_events(events);
    }
    pub(crate) fn failure_reporter(&self) -> Arc<dyn UdpFailure> {
        self.inner.failure_reporter.get().unwrap().clone()
    }

    pub(crate) fn can_receive_error(&self, source: IpEndpoint, ifindex: u32) -> bool {
        let open = self.open.lock();
        if !*open { return false; }
        let bound = self.bound.receive_endpoint();
        self.bound.device().is_none_or(|device| device == ifindex)
            && bound.port == source.port
            && (bound.addr.is_unspecified() || bound.addr == source.addr)
    }

    pub(crate) fn matches_error_destination(&self, destination: IpEndpoint) -> bool {
        self.inner.errors.lock().peer.is_none_or(|peer| peer == destination)
    }

    pub(crate) fn path_mtu_egress(&self, source: IpEndpoint, destination: IpEndpoint) -> Option<u32> {
        let open = self.open.lock();
        if !*open { return None; }
        let errors = self.inner.errors.lock();
        if errors.ignore_path_mtu || errors.peer.is_some_and(|peer| peer != destination) { return None; }
        errors.sent_paths.iter().rev()
            .find(|path| path.source == source && path.destination == destination)
            .map(|path| path.ifindex)
    }

    pub(crate) fn report_error(&self, mut error: UdpError) {
        let open = self.open.lock();
        if !*open { return; }
        let mut errors = self.inner.errors.lock();
        if errors.ignore_fragmentation_error && matches!(error.origin, UdpErrorOrigin::Icmp { type_: 3, code: 4, .. })
            || errors.peer.is_some_and(|peer| peer != error.destination)
            || errors.peer.is_none() && !errors.recverr
            || !errors.recverr && !error.origin.is_hard()
        {
            return;
        }
        errors.pending = Some(error.origin);
        error.timestamp_ns = E::wall_time_ns();
        if errors.recverr {
            let size = error.payload.len();
            if size <= UDP_RECV_PAYLOAD_LEN {
                while errors.queued_bytes + size > UDP_RECV_PAYLOAD_LEN
                    || errors.queue.len() >= UDP_METADATA_LEN
                {
                    let Some(old) = errors.queue.pop_front() else { break };
                    errors.queued_bytes -= old.payload.len();
                }
                errors.queued_bytes += size;
                errors.queue.push_back(error);
            }
        }
        drop(errors);
        drop(open);
        self.notify_events(SocketEvents::HAS_ERROR);
    }

    /// Tries to process an incoming packet and returns whether the packet is processed.
    pub(crate) fn process(
        &self,
        ip_repr: &IpRepr,
        udp_repr: &UdpRepr,
        udp_payload: PacketSlice<'_>,
        tos: u8,
        ifindex: u32,
    ) -> bool {
        let open = self.open.lock();
        if !*open || !self.accepts(ip_repr, udp_repr, ifindex) {
            return false;
        }

        let ttl = match ip_repr {
            IpRepr::Ipv4(header) => header.hop_limit,
            IpRepr::Ipv6(header) => header.hop_limit,
        };
        let udp = UdpMetadata {
            endpoint: IpEndpoint::new(ip_repr.src_addr(), udp_repr.src_port),
            local_address: Some(ip_repr.dst_addr()),
            meta: Default::default(),
        };
        let metadata = ReceivedMetadata { udp, timestamp_ns: E::wall_time_ns(), ttl, tos, ifindex };
        let mut received = self.inner.received.lock();
        let Ok(buffer) = received.enqueue(udp_payload.len(), metadata) else {
            return true;
        };
        udp_payload.copy_to_slice(buffer);
        drop(received);
        drop(open);

        self.notify_events(SocketEvents::CAN_RECV);

        true
    }

    fn accepts(&self, ip_repr: &IpRepr, udp_repr: &UdpRepr, ifindex: u32) -> bool {
        let bound = self.bound.receive_endpoint();
        let peer = IpEndpoint::new(ip_repr.src_addr(), udp_repr.src_port);
        self.bound.device().is_none_or(|device| device == ifindex)
            && (bound.addr.is_unspecified() || ip_repr.dst_addr() == bound.addr)
            && udp_repr.dst_port == bound.port
            && self.inner.errors.lock().peer.is_none_or(|connected| connected == peer)
    }

    pub(crate) fn receive_priority(&self, ip_repr: &IpRepr, udp_repr: &UdpRepr, ifindex: u32) -> Option<u8> {
        let open = self.open.lock();
        if !*open || !self.accepts(ip_repr, udp_repr, ifindex) { return None; }
        let specific = !self.bound.receive_endpoint().addr.is_unspecified();
        let connected = self.inner.errors.lock().peer.is_some();
        Some(u8::from(specific) * 4 + u8::from(connected) * 2 + u8::from(self.bound.device().is_some()))
    }

    /// Tries to generate an outgoing packet and dispatches the generated packet.
    pub(crate) fn dispatch<D>(&self, ifindex: u32, cx: &mut Context, dispatch: D)
    where
        D: FnOnce(&mut Context, &IpRepr, &UdpRepr, &[u8], u8, UdpNextHop, UdpFragmentation, Option<&UdpIpv4Options>),
    {
        let open = self.open.lock();
        if !*open { return; }
        let mut queue = self.inner.tx.lock();
        let Some(packet) = queue.take_for(ifindex) else { return };
        drop(queue);
        drop(open);
        let ip_repr = IpRepr::new(packet.source, packet.destination.addr, IpProtocol::Udp,
            UDP_HEADER_LEN + packet.payload.len(), packet.ttl);
        let udp_repr = UdpRepr { src_port: self.bound.endpoint().port, dst_port: packet.destination.port };
        dispatch(cx, &ip_repr, &udp_repr, &packet.payload, packet.tos, packet.next_hop, packet.fragmentation, packet.ipv4_options.as_ref());
        let open = self.open.lock();
        let notify_send = *open;
        let notify_stamp = *open && packet.tag != 0;
        if notify_stamp {
            let mut stamps = self.inner.tx_stamps.lock();
            if stamps.len() == MAX_PENDING_TX_STAMPS { stamps.pop_front(); }
            stamps.push_back(TxTimestamp { tag: packet.tag, wall_time_ns: E::wall_time_ns() });
            drop(stamps);
        }
        drop(open);
        if notify_stamp { self.notify_events(SocketEvents::HAS_ERROR); }
        if notify_send { self.notify_events(SocketEvents::CAN_SEND); }
    }

    /// Returns whether the socket _may_ generate an outgoing packet.
    ///
    /// The check is intended to be lock-free and fast, but may have false positives.
    pub(crate) fn need_dispatch(&self, ifindex: u32) -> bool {
        let open = self.open.lock();
        *open && self.inner.tx.lock().packets.iter().any(|packet| packet.iface == ifindex)
    }
}

impl<E: Ext> UdpSocket<E> {
    pub fn set_hop_limit(&self, limit: u8) {
        self.0.inner.ttl.store(limit, Ordering::Relaxed);
    }

    pub fn set_error_peer(&self, peer: Option<IpEndpoint>) {
        self.0.inner.errors.lock().peer = peer;
    }

    pub fn set_receive_address(&self, address: IpAddress) {
        let open = self.0.open.lock();
        if *open { self.0.bound.set_receive_address(address); }
    }

    pub fn set_ignore_fragmentation_error(&self, ignore: bool) {
        self.0.inner.errors.lock().ignore_fragmentation_error = ignore;
    }

    pub fn set_ignore_path_mtu(&self, ignore: bool) {
        self.0.inner.errors.lock().ignore_path_mtu = ignore;
    }

    pub fn set_receive_errors(&self, enabled: bool) {
        let mut errors = self.0.inner.errors.lock();
        errors.recverr = enabled;
        if !enabled {
            errors.queue.clear();
            errors.queued_bytes = 0;
        }
    }

    pub fn take_pending_error(&self) -> Option<UdpErrorOrigin> {
        self.0.inner.errors.lock().pending.take()
    }

    pub fn pop_network_error(&self) -> Option<UdpError> {
        let mut errors = self.0.inner.errors.lock();
        let error = errors.queue.pop_front()?;
        errors.queued_bytes -= error.payload.len();
        errors.pending = errors.queue.front().map(|next| next.origin);
        Some(error)
    }

    pub fn has_network_error(&self) -> bool {
        let errors = self.0.inner.errors.lock();
        errors.pending.is_some() || !errors.queue.is_empty()
    }

    /// Binds to a specified endpoint.
    ///
    /// Polling the iface is _not_ required after this method succeeds.
    pub fn new_bind(bound: UdpReservation<E>, observer: E::UdpEventObserver) -> Self {
        let registry = bound.registry().clone();
        let inner = UdpSocketInner {
            tx: SpinLock::new(TxQueue::default()),
            ttl: AtomicU8::new(64),
            received: SpinLock::new(PacketBuffer::new(
                vec![PacketMetadata::<ReceivedMetadata>::EMPTY; UDP_METADATA_LEN],
                vec![0; UDP_RECV_PAYLOAD_LEN],
            )),
            tx_stamps: SpinLock::new(VecDeque::new()),
            errors: SpinLock::new(UdpErrors::default()),
            failure_reporter: Once::new(),
        };

        let socket = Self(Arc::new(UdpSocketBg { bound, inner, observer, open: SpinLock::new(true) }));
        socket.0.inner.failure_reporter.call_once(|| {
            Arc::new(UdpFailureReporter { socket: Arc::downgrade(&socket.0) })
        });
        registry.register(&socket.0);
        socket
    }

    /// Sends some data.
    ///
    /// Polling the iface is _always_ required after this method succeeds.
    ///
    /// A nonzero `meta.meta.id` asks for a transmit timestamp, which [`Self::pop_tx_timestamp`]
    /// returns after the packet leaves the interface.
    pub fn send<F, R, Err>(
        &self,
        size: usize,
        meta: impl Into<UdpMetadata>,
        iface: u32,
        source: IpAddress,
        tos: u8,
        next_hop: UdpNextHop,
        fragmentation: UdpFragmentation,
        ipv4_options: Option<UdpIpv4Options>,
        f: F,
    ) -> Result<Result<R, Err>, SendError>
    where
        F: FnOnce(&mut [u8]) -> Result<R, Err>,
    {
        if size > UDP_SEND_PAYLOAD_LEN {
            return Err(SendError::TooLarge);
        }
        let mut payload = vec![0; size];
        let mut queue = self.0.inner.tx.lock();
        if !queue.can_enqueue(size) {
            return Err(SendError::BufferFull);
        }
        let result = f(&mut payload);
        if result.is_err() { return Ok(result); }
        let meta = meta.into();
        {
            let mut errors = self.0.inner.errors.lock();
            let source = IpEndpoint::new(source, self.0.bound.endpoint().port);
            let destination = IpEndpoint::new(ipv4_options.as_ref().and_then(UdpIpv4Options::first_hop)
                .map_or(meta.endpoint.addr, IpAddress::Ipv4), meta.endpoint.port);
            errors.sent_paths.retain(|path| path.source != source || path.destination != destination);
            if errors.sent_paths.len() == 64 { errors.sent_paths.pop_front(); }
            errors.sent_paths.push_back(SentPath { source, destination, ifindex: iface });
        }
        queue.enqueue(TxDatagram { iface, source, destination: meta.endpoint,
            ttl: self.0.inner.ttl.load(Ordering::Relaxed), tos, next_hop, fragmentation, ipv4_options, tag: meta.meta.id, payload })?;
        Ok(result)
    }

    /// Receives some data.
    ///
    /// `copy_fn` also gets the wall-clock time, in nanoseconds since the Unix epoch, at which the
    /// packet arrived, the received hop limit, and the IPv4 type of service.
    ///
    /// Polling the iface is _not_ required after this method succeeds.
    pub fn recv<CopyFn, R>(
        &self,
        behavior: ReceiveBehavior,
        copy_fn: CopyFn,
    ) -> Result<R, smoltcp::socket::udp::RecvError>
    where
        CopyFn: FnOnce(&[u8], UdpMetadata, u64, u8, u8, u32) -> R,
    {
        let mut received = self.0.inner.received.lock();
        let (metadata, data): (ReceivedMetadata, &[u8]) = match behavior {
            ReceiveBehavior::Recv => {
                let (metadata, data) = received.dequeue().map_err(|_| smoltcp::socket::udp::RecvError::Exhausted)?;
                (metadata, &*data)
            }
            ReceiveBehavior::Peek => {
                let (metadata, data) = received.peek().map_err(|_| smoltcp::socket::udp::RecvError::Exhausted)?;
                (*metadata, data)
            }
        };
        Ok(copy_fn(data, metadata.udp, metadata.timestamp_ns, metadata.ttl, metadata.tos, metadata.ifindex))
    }

    /// Takes the oldest pending transmit timestamp.
    pub fn pop_tx_timestamp(&self) -> Option<TxTimestamp> {
        self.0.inner.tx_stamps.lock().pop_front()
    }

    /// Returns whether a transmit timestamp is pending.
    pub fn has_tx_timestamp(&self) -> bool {
        !self.0.inner.tx_stamps.lock().is_empty()
    }

    pub fn can_recv(&self) -> bool {
        self.0.inner.received.lock().peek().is_ok()
    }

    pub fn can_send(&self) -> bool {
        self.0.inner.tx.lock().packets.len() < UDP_METADATA_LEN
    }

    pub fn local_endpoint(&self) -> IpEndpoint { self.0.bound.endpoint() }

    pub fn bound_port(&self) -> &UdpReservation<E> { &self.0.bound }
}

#[cfg(ktest)]
mod test {
    use ostd::prelude::ktest;
    use smoltcp::wire::Ipv4Address;
    use super::*;

    struct TestExt;
    struct TestSchedule;

    impl crate::iface::ScheduleNextPoll for TestSchedule {
        fn schedule_next_poll(&self, _ms: Option<u64>) {}
    }

    impl Ext for TestExt {
        type ScheduleNextPoll = TestSchedule;
        type TcpEventObserver = ();
        type UdpEventObserver = ();
        fn wall_time_ns() -> u64 { 0 }
    }

    #[ktest]
    fn closed_socket_in_poll_snapshot_cannot_match_error() {
        let registry = crate::iface::UdpRegistry::<TestExt>::new();
        let local = IpEndpoint::new(IpAddress::Ipv4(Ipv4Address::LOCALHOST), 1234);
        let config = crate::iface::BindPortConfig::new(local, false);
        let owner = Arc::new(core::sync::atomic::AtomicU32::new(0));
        let reservation = registry.bind(config, None, false, owner).unwrap();
        let socket = UdpSocket::new_bind(reservation, ());
        let snapshot = registry.sockets().pop().unwrap();
        assert!(snapshot.can_receive_error(local, 1));
        drop(socket);
        assert!(!snapshot.can_receive_error(local, 1));
    }

    #[ktest]
    fn path_feedback_uses_the_recent_sent_interface() {
        let registry = crate::iface::UdpRegistry::<TestExt>::new();
        let address = IpAddress::Ipv4(Ipv4Address::LOCALHOST);
        let local = IpEndpoint::new(address, 1234);
        let config = crate::iface::BindPortConfig::new(local, false);
        let owner = Arc::new(core::sync::atomic::AtomicU32::new(0));
        let reservation = registry.bind(config, None, false, owner).unwrap();
        let socket = UdpSocket::new_bind(reservation, ());
        let snapshot = registry.sockets().pop().unwrap();
        for port in 1..=65 {
            let destination = IpEndpoint::new(address, port);
            socket.send(0, destination, 7, address, 0, UdpNextHop::Routed,
                UdpFragmentation::DontFragment, None, |_| Ok::<(), ()>(())).unwrap().unwrap();
        }
        assert!(snapshot.path_mtu_egress(local, IpEndpoint::new(address, 1)).is_none());
        assert_eq!(snapshot.path_mtu_egress(local, IpEndpoint::new(address, 65)), Some(7));
        drop(socket);
        assert!(snapshot.path_mtu_egress(local, IpEndpoint::new(address, 65)).is_none());
    }

    fn packet(iface: u32, size: usize) -> TxDatagram {
        let address = IpAddress::Ipv4(Ipv4Address::LOCALHOST);
        TxDatagram { iface, source: address, destination: IpEndpoint::new(address, 1234),
            ttl: 64, tos: 0, next_hop: UdpNextHop::Routed, fragmentation: UdpFragmentation::DontFragment, ipv4_options: None, tag: 0, payload: vec![0; size] }
    }

    #[ktest]
    fn tx_queue_respects_capacity_and_selected_interface() {
        let mut queue = TxQueue::default();
        assert!(queue.enqueue(packet(1, UDP_SEND_PAYLOAD_LEN)).is_ok());
        assert!(queue.enqueue(packet(2, 1)).is_err());
        assert!(queue.enqueue(packet(2, 0)).is_ok());
        assert_eq!(queue.take_for(2).unwrap().payload.len(), 0);
        assert_eq!(queue.take_for(1).unwrap().payload.len(), UDP_SEND_PAYLOAD_LEN);
        for _ in 0..UDP_METADATA_LEN { assert!(queue.enqueue(packet(1, 0)).is_ok()); }
        assert!(queue.enqueue(packet(1, 0)).is_err());
        assert!(queue.take_for(1).is_some());
        assert!(queue.enqueue(packet(1, 0)).is_ok());
    }
}
