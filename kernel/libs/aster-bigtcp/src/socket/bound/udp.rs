// SPDX-License-Identifier: MPL-2.0

use alloc::{boxed::Box, collections::VecDeque, sync::{Arc, Weak}, vec, vec::Vec};
use core::sync::atomic::{AtomicBool, Ordering};

use aster_softirq::BottomHalfDisabled;
use ostd::sync::SpinLock;
use spin::Once;
use smoltcp::{
    iface::Context,
    socket::udp::UdpMetadata,
    storage::{PacketBuffer, PacketMetadata, SliceLike},
    wire::{IpAddress, IpEndpoint, IpListenEndpoint, IpRepr, UdpRepr},
};

use super::{
    ReceiveBehavior,
    common::{Inner, Socket, SocketBg},
};
use crate::{
    errors::udp::SendError,
    ext::Ext,
    iface::{BoundUdpPort, PacketSlice, UdpFailure},
    socket::{
        RawUdpSocket,
        event::SocketEvents,
        unbound::{UDP_METADATA_LEN, UDP_RECV_PAYLOAD_LEN, new_udp_socket},
    },
};

pub type UdpSocket<E> = Socket<UdpSocketInner, E>;

/// States needed by [`UdpSocketBg`].
pub struct UdpSocketInner {
    socket: SpinLock<Box<RawUdpSocket>, BottomHalfDisabled>,
    need_dispatch: AtomicBool,
    received: SpinLock<PacketBuffer<'static, ReceivedMetadata>, BottomHalfDisabled>,
    tx_tos: SpinLock<VecDeque<u8>, BottomHalfDisabled>,
    tx_stamps: SpinLock<VecDeque<TxTimestamp>, BottomHalfDisabled>,
    errors: SpinLock<UdpErrors, BottomHalfDisabled>,
    failure_reporter: Once<Arc<dyn UdpFailure>>,
}

#[derive(Clone, Copy)]
struct ReceivedMetadata {
    udp: UdpMetadata,
    timestamp_ns: u64,
    ttl: u8,
    tos: u8,
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
    pending: Option<UdpErrorOrigin>,
    queue: VecDeque<UdpError>,
    queued_bytes: usize,
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

impl<E: Ext> Inner<E> for UdpSocketInner {
    type BoundPort = BoundUdpPort<E>;
    type Observer = E::UdpEventObserver;

    fn on_drop(this: &Arc<SocketBg<Self, E>>) {
        this.inner.socket.lock().close();

        // A UDP socket can be removed immediately.
        this.bound.iface().common().remove_udp_socket(this);
    }
}

pub(crate) type UdpSocketBg<E> = SocketBg<UdpSocketInner, E>;

impl<E: Ext> UdpSocketBg<E> {
    pub(crate) fn failure_reporter(&self) -> Arc<dyn UdpFailure> {
        self.inner.failure_reporter.get().unwrap().clone()
    }

    pub(crate) fn can_receive_error(&self, source: IpEndpoint) -> bool {
        self.bound.port() == source.port
            && (self.bound.addr().is_unspecified() || *self.bound.addr() == source.addr)
    }

    pub(crate) fn report_error(&self, mut error: UdpError) {
        let mut errors = self.inner.errors.lock();
        if errors.peer.is_some_and(|peer| peer != error.destination)
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
        self.notify_events(SocketEvents::HAS_ERROR);
    }

    /// Tries to process an incoming packet and returns whether the packet is processed.
    pub(crate) fn process(
        &self,
        ip_repr: &IpRepr,
        udp_repr: &UdpRepr,
        udp_payload: PacketSlice<'_>,
        tos: u8,
    ) -> bool {
        if !self.accepts(ip_repr, udp_repr) {
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
        let metadata = ReceivedMetadata { udp, timestamp_ns: E::wall_time_ns(), ttl, tos };
        let mut received = self.inner.received.lock();
        let Ok(buffer) = received.enqueue(udp_payload.len(), metadata) else {
            return true;
        };
        udp_payload.copy_to_slice(buffer);
        drop(received);

        self.notify_events(SocketEvents::CAN_RECV);

        true
    }

    fn accepts(&self, ip_repr: &IpRepr, udp_repr: &UdpRepr) -> bool {
        // This must be stricter than `RawUdpSocket::accepts` so that `RawUdpSocket::process` is
        // guaranteed to work correctly if this method returns true.
        //
        // `RawUdpSocket::accepts` accepts all incoming broadcast and multicast packets, which is not
        // what we want.
        let bound_addr = self.bound.addr();
        (bound_addr.is_unspecified() || ip_repr.dst_addr() == *bound_addr)
            && udp_repr.dst_port == self.bound.port()
    }

    /// Tries to generate an outgoing packet and dispatches the generated packet.
    pub(crate) fn dispatch<D>(&self, cx: &mut Context, dispatch: D)
    where
        D: FnOnce(&mut Context, &IpRepr, &UdpRepr, &[u8], u8),
    {
        let mut socket = self.inner.socket.lock();

        let mut stamped = false;
        let mut queued_tos = self.inner.tx_tos.lock();
        let tos = queued_tos.pop_front();
        socket
            .dispatch(cx, |cx, meta, (ip_repr, udp_repr, udp_payload)| {
                dispatch(cx, &ip_repr, &udp_repr, udp_payload, tos.expect("queued UDP packet has TOS"));
                if meta.id != 0 {
                    let mut stamps = self.inner.tx_stamps.lock();
                    if stamps.len() == MAX_PENDING_TX_STAMPS {
                        stamps.pop_front();
                    }
                    stamps.push_back(TxTimestamp {
                        tag: meta.id,
                        wall_time_ns: E::wall_time_ns(),
                    });
                    stamped = true;
                }
                Ok::<(), ()>(())
            })
            .unwrap();
        if stamped {
            self.notify_events(SocketEvents::HAS_ERROR);
        }

        // For UDP, dequeuing a packet means that we can queue more packets.
        self.notify_events(SocketEvents::CAN_SEND);

        self.inner
            .need_dispatch
            .store(!queued_tos.is_empty(), Ordering::Relaxed);
    }

    /// Returns whether the socket _may_ generate an outgoing packet.
    ///
    /// The check is intended to be lock-free and fast, but may have false positives.
    pub(crate) fn need_dispatch(&self) -> bool {
        self.inner.need_dispatch.load(Ordering::Relaxed)
    }
}

impl<E: Ext> UdpSocket<E> {
    pub fn set_hop_limit(&self, limit: u8) {
        self.0.inner.socket.lock().set_hop_limit(Some(limit));
    }

    pub fn set_error_peer(&self, peer: Option<IpEndpoint>) {
        self.0.inner.errors.lock().peer = peer;
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
    pub fn new_bind(
        bound: BoundUdpPort<E>,
        observer: E::UdpEventObserver,
    ) -> Result<Self, (BoundUdpPort<E>, smoltcp::socket::udp::BindError)> {
        let local_endpoint = {
            let mut endpoint = bound.endpoint();

            // This is the address used to send packets. Source addresses can never be the broadcast
            // address, even if it is the address that the socket binds to.
            let interface = bound.iface().common().interface();
            endpoint.addr = interface.map_broadcast_to_local(endpoint.addr);

            endpoint
        };

        let socket = {
            let mut socket = new_udp_socket();

            let listen_endpoint = IpListenEndpoint {
                addr: (!local_endpoint.addr.is_unspecified()).then_some(local_endpoint.addr),
                port: local_endpoint.port,
            };
            if let Err(err) = socket.bind(listen_endpoint) {
                return Err((bound, err));
            }

            socket
        };

        let inner = UdpSocketInner {
            socket: SpinLock::new(socket),
            need_dispatch: AtomicBool::new(false),
            received: SpinLock::new(PacketBuffer::new(
                vec![PacketMetadata::<ReceivedMetadata>::EMPTY; UDP_METADATA_LEN],
                vec![0; UDP_RECV_PAYLOAD_LEN],
            )),
            tx_tos: SpinLock::new(VecDeque::new()),
            tx_stamps: SpinLock::new(VecDeque::new()),
            errors: SpinLock::new(UdpErrors::default()),
            failure_reporter: Once::new(),
        };

        let socket = Self::new(bound, inner);
        socket.inner().inner.failure_reporter.call_once(|| {
            Arc::new(UdpFailureReporter { socket: Arc::downgrade(socket.inner()) })
        });
        socket.init_observer(observer);
        socket
            .iface()
            .common()
            .register_udp_socket(socket.inner().clone());

        Ok(socket)
    }

    /// Sends some data.
    ///
    /// Polling the iface is _always_ required after this method succeeds.
    ///
    /// A nonzero `meta.meta.id` asks for a transmit timestamp, which [`Self::pop_tx_timestamp`]
    /// returns after the packet leaves the interface.
    pub fn send<F, R>(
        &self,
        size: usize,
        meta: impl Into<UdpMetadata>,
        tos: u8,
        f: F,
    ) -> Result<R, SendError>
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut socket = self.0.inner.socket.lock();

        if size > socket.payload_send_capacity() {
            return Err(SendError::TooLarge);
        }

        let buffer = socket.send(size, meta)?;
        self.0.inner.tx_tos.lock().push_back(tos);
        let result = f(buffer);

        self.0
            .inner
            .need_dispatch
            .store(true, Ordering::Relaxed);

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
        CopyFn: FnOnce(&[u8], UdpMetadata, u64, u8, u8) -> R,
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
        Ok(copy_fn(data, metadata.udp, metadata.timestamp_ns, metadata.ttl, metadata.tos))
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
        self.0.inner.socket.lock().can_send()
    }
}
