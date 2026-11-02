// SPDX-License-Identifier: MPL-2.0

use alloc::{boxed::Box, collections::VecDeque, sync::Arc};
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

use aster_softirq::BottomHalfDisabled;
use ostd::sync::SpinLock;
use smoltcp::{
    iface::Context,
    socket::udp::UdpMetadata,
    wire::{IpListenEndpoint, IpRepr, UdpRepr},
};

use super::{
    ReceiveBehavior,
    common::{Inner, Socket, SocketBg},
};
use crate::{
    errors::udp::SendError,
    ext::Ext,
    iface::{BoundUdpPort, PacketSlice},
    socket::{
        RawUdpSocket,
        event::SocketEvents,
        unbound::{UDP_METADATA_LEN, new_udp_socket},
    },
};

pub type UdpSocket<E> = Socket<UdpSocketInner, E>;

/// States needed by [`UdpSocketBg`].
pub struct UdpSocketInner {
    socket: SpinLock<Box<RawUdpSocket>, BottomHalfDisabled>,
    need_dispatch: AtomicBool,
    rx_times: Box<[AtomicU64]>,
    rx_counter: AtomicU32,
    tx_stamps: SpinLock<VecDeque<TxTimestamp>, BottomHalfDisabled>,
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
    /// Tries to process an incoming packet and returns whether the packet is processed.
    pub(crate) fn process(
        &self,
        cx: &mut Context,
        ip_repr: &IpRepr,
        udp_repr: &UdpRepr,
        udp_payload: PacketSlice<'_>,
    ) -> bool {
        if !self.accepts(ip_repr, udp_repr) {
            return false;
        }

        let mut socket = self.inner.socket.lock();

        let id = self.inner.rx_counter.fetch_add(1, Ordering::Relaxed);
        let slot = id as usize % self.inner.rx_times.len();
        self.inner.rx_times[slot].store(E::wall_time_ns(), Ordering::Relaxed);
        let mut meta = smoltcp::phy::PacketMeta::default();
        meta.id = id;

        socket.process(
            cx,
            meta,
            ip_repr,
            udp_repr,
            udp_payload,
        );

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
        D: FnOnce(&mut Context, &IpRepr, &UdpRepr, &[u8]),
    {
        let mut socket = self.inner.socket.lock();

        let mut stamped = false;
        socket
            .dispatch(cx, |cx, meta, (ip_repr, udp_repr, udp_payload)| {
                dispatch(cx, &ip_repr, &udp_repr, udp_payload);
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
            .store(socket.send_queue() > 0, Ordering::Relaxed);
    }

    /// Returns whether the socket _may_ generate an outgoing packet.
    ///
    /// The check is intended to be lock-free and fast, but may have false positives.
    pub(crate) fn need_dispatch(&self) -> bool {
        self.inner.need_dispatch.load(Ordering::Relaxed)
    }
}

impl<E: Ext> UdpSocket<E> {
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

        let socket_rx_slots = UDP_METADATA_LEN;
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
            rx_times: (0..socket_rx_slots).map(|_| AtomicU64::new(0)).collect(),
            rx_counter: AtomicU32::new(0),
            tx_stamps: SpinLock::new(VecDeque::new()),
        };

        let socket = Self::new(bound, inner);
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
        let result = f(buffer);

        self.0
            .inner
            .need_dispatch
            .store(socket.send_queue() > 0, Ordering::Relaxed);

        Ok(result)
    }

    /// Receives some data.
    ///
    /// `copy_fn` also gets the wall-clock time, in nanoseconds since the Unix epoch, at which the
    /// packet arrived.
    ///
    /// Polling the iface is _not_ required after this method succeeds.
    pub fn recv<CopyFn, R>(
        &self,
        behavior: ReceiveBehavior,
        copy_fn: CopyFn,
    ) -> Result<R, smoltcp::socket::udp::RecvError>
    where
        CopyFn: FnOnce(&[u8], UdpMetadata, u64) -> R,
    {
        let mut socket = self.0.inner.socket.lock();

        let (data, meta) = match behavior {
            ReceiveBehavior::Recv => socket.recv()?,
            ReceiveBehavior::Peek => {
                let (data, meta) = socket.peek()?;
                (data, *meta)
            }
        };
        let slot = meta.meta.id as usize % self.0.inner.rx_times.len();
        let arrived_at = self.0.inner.rx_times[slot].load(Ordering::Relaxed);
        let result = copy_fn(data, meta, arrived_at);

        Ok(result)
    }

    /// Takes the oldest pending transmit timestamp.
    pub fn pop_tx_timestamp(&self) -> Option<TxTimestamp> {
        self.0.inner.tx_stamps.lock().pop_front()
    }

    /// Returns whether a transmit timestamp is pending.
    pub fn has_tx_timestamp(&self) -> bool {
        !self.0.inner.tx_stamps.lock().is_empty()
    }

    /// Calls `f` with an immutable reference to the associated [`RawUdpSocket`].
    //
    // NOTE: If a mutable reference is required, add a method above that correctly updates the next
    // polling time.
    pub fn raw_with<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&RawUdpSocket) -> R,
    {
        let socket = self.0.inner.socket.lock();
        f(&socket)
    }
}
