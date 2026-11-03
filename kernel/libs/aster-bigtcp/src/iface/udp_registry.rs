// SPDX-License-Identifier: MPL-2.0

use alloc::{collections::BTreeMap, sync::{Arc, Weak}, vec::Vec};
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use aster_softirq::BottomHalfDisabled;
use ostd::sync::SpinLock;
use smoltcp::wire::{IpAddress, IpEndpoint};

use super::BindPortConfig;
use crate::{errors::BindError, ext::Ext, socket::UdpSocketBg};

const EPHEMERAL_START: u16 = 32768;
const EPHEMERAL_END: u16 = 60999;

pub struct UdpRegistry<E: Ext> {
    state: SpinLock<State<E>, BottomHalfDisabled>,
}

struct State<E: Ext> {
    bindings: BTreeMap<u64, Binding>,
    sockets: Vec<Weak<UdpSocketBg<E>>>,
    next_id: u64,
    next_port: u16,
}

#[derive(Clone)]
struct Binding {
    endpoint: IpEndpoint,
    device: Option<u32>,
    reuse: bool,
    reuse_port: bool,
    owner: Arc<AtomicU32>,
}

impl<E: Ext> UdpRegistry<E> {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            state: SpinLock::new(State {
                bindings: BTreeMap::new(),
                sockets: Vec::new(),
                next_id: 0,
                next_port: EPHEMERAL_START,
            }),
        })
    }

    pub fn bind(self: &Arc<Self>, config: BindPortConfig, device: Option<u32>, reuse_port: bool, owner: Arc<AtomicU32>) -> Result<UdpReservation<E>, BindError> {
        let mut state = self.state.lock();
        let addr = config.addr();
        let reuse = config.can_reuse();
        let port = if let Some(port) = config.port() {
            if state.conflicts(IpEndpoint::new(addr, port), device, reuse, reuse_port, &owner) {
                return Err(BindError::InUse);
            }
            port
        } else {
            let start = state.next_port;
            let mut port = start;
            loop {
                if !state.conflicts(IpEndpoint::new(addr, port), device, false, false, &owner) {
                    state.next_port = if port == EPHEMERAL_END { EPHEMERAL_START } else { port + 1 };
                    break port;
                }
                port = if port == EPHEMERAL_END { EPHEMERAL_START } else { port + 1 };
                if port == start {
                    return Err(BindError::Exhausted);
                }
            }
        };
        let id = loop {
            let id = state.next_id;
            state.next_id = state.next_id.wrapping_add(1);
            if !state.bindings.contains_key(&id) {
                break id;
            }
        };
        let endpoint = IpEndpoint::new(addr, port);
        state.bindings.insert(id, Binding { endpoint, device, reuse, reuse_port, owner: owner.clone() });
        Ok(UdpReservation { registry: self.clone(), id, endpoint, device, owner,
            reuse: AtomicBool::new(reuse), reuse_port: AtomicBool::new(reuse_port), released: AtomicBool::new(false) })
    }

    pub(crate) fn register(&self, socket: &Arc<UdpSocketBg<E>>) {
        self.state.lock().sockets.push(Arc::downgrade(socket));
    }

    pub(crate) fn unregister(&self, socket: &Arc<UdpSocketBg<E>>) {
        let target = Arc::downgrade(socket);
        self.state.lock().sockets.retain(|entry| !Weak::ptr_eq(entry, &target));
    }

    pub(crate) fn sockets(&self) -> Vec<Arc<UdpSocketBg<E>>> {
        let mut state = self.state.lock();
        let mut sockets = Vec::new();
        state.sockets.retain(|socket| {
            if let Some(socket) = socket.upgrade() {
                sockets.push(socket);
                true
            } else {
                false
            }
        });
        sockets
    }
}

impl<E: Ext> State<E> {
    fn conflicts(&self, endpoint: IpEndpoint, device: Option<u32>, reuse: bool, reuse_port: bool, owner: &AtomicU32) -> bool {
        self.bindings.values().any(|binding| {
            binding.endpoint.port == endpoint.port
                && devices_overlap(binding.device, device)
                && addresses_overlap(binding.endpoint.addr, endpoint.addr)
                && !(binding.reuse && reuse || binding.reuse_port && reuse_port
                    && binding.owner.load(Ordering::Acquire) == owner.load(Ordering::Acquire))
        })
    }
}

fn devices_overlap(a: Option<u32>, b: Option<u32>) -> bool {
    a.is_none() || b.is_none() || a == b
}

fn addresses_overlap(a: IpAddress, b: IpAddress) -> bool {
    match (a, b) {
        (IpAddress::Ipv4(a), IpAddress::Ipv4(b)) => a == b || a.is_unspecified() || b.is_unspecified(),
        (IpAddress::Ipv6(a), IpAddress::Ipv6(b)) => a == b || a.is_unspecified() || b.is_unspecified(),
        _ => false,
    }
}

pub struct UdpReservation<E: Ext> {
    registry: Arc<UdpRegistry<E>>,
    id: u64,
    endpoint: IpEndpoint,
    device: Option<u32>,
    owner: Arc<AtomicU32>,
    reuse: AtomicBool,
    reuse_port: AtomicBool,
    released: AtomicBool,
}

impl<E: Ext> UdpReservation<E> {
    pub fn endpoint(&self) -> IpEndpoint { self.endpoint }

    pub fn device(&self) -> Option<u32> { self.device }

    pub(crate) fn same_reuse_port_group(&self, other: &Self) -> bool {
        self.reuse_port.load(Ordering::Acquire) && other.reuse_port.load(Ordering::Acquire)
            && self.owner.load(Ordering::Acquire) == other.owner.load(Ordering::Acquire)
            && self.endpoint == other.endpoint && self.device == other.device
    }

    pub(crate) fn registry(&self) -> &Arc<UdpRegistry<E>> { &self.registry }

    pub(crate) fn release(&self) {
        if !self.released.swap(true, Ordering::AcqRel) {
            self.registry.state.lock().bindings.remove(&self.id);
        }
    }

    pub fn set_can_reuse(&self, reuse: bool) {
        let mut state = self.registry.state.lock();
        if self.reuse.load(Ordering::Relaxed) != reuse {
            state.bindings.get_mut(&self.id).expect("UDP reservation exists").reuse = reuse;
            self.reuse.store(reuse, Ordering::Relaxed);
        }
    }

    pub fn set_reuse_port(&self, reuse_port: bool) {
        let mut state = self.registry.state.lock();
        state.bindings.get_mut(&self.id).expect("UDP reservation exists").reuse_port = reuse_port;
        self.reuse_port.store(reuse_port, Ordering::Release);
    }
}

impl<E: Ext> Drop for UdpReservation<E> {
    fn drop(&mut self) {
        self.release();
    }
}
