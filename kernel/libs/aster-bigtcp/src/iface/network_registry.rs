// SPDX-License-Identifier: MPL-2.0

use alloc::{collections::{BTreeMap, VecDeque}, sync::{Arc, Weak}, vec::Vec};
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use aster_softirq::BottomHalfDisabled;
use ostd::sync::SpinLock;
use smoltcp::wire::{IpAddress, IpEndpoint, Ipv4Address, Ipv4Cidr};

use super::BindPortConfig;
use crate::{errors::BindError, ext::Ext, packet::{NetworkLayer, RxPacket}, socket::UdpSocketBg};

const EPHEMERAL_START: u16 = 32768;
const EPHEMERAL_END: u16 = 60999;

pub struct NetworkRegistry<E: Ext> {
    state: SpinLock<State<E>, BottomHalfDisabled>,
    path_mtu: SpinLock<Vec<PathMtuEntry>, BottomHalfDisabled>,
    local_ingress: SpinLock<LocalIngress, BottomHalfDisabled>,
}

#[derive(Default)]
struct LocalIngress {
    addresses: BTreeMap<u32, (bool, Vec<Ipv4Address>)>,
    packets: BTreeMap<u32, VecDeque<RxPacket<NetworkLayer>>>,
}

struct PathMtuEntry {
    ifindex: u32,
    destination: IpAddress,
    route: super::PathMtuRoute,
    mtu: usize,
    locked: bool,
    expires_at_ms: i64,
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

impl<E: Ext> NetworkRegistry<E> {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            state: SpinLock::new(State {
                bindings: BTreeMap::new(),
                sockets: Vec::new(),
                next_id: 0,
                next_port: EPHEMERAL_START,
            }),
            path_mtu: SpinLock::new(Vec::new()),
            local_ingress: SpinLock::new(LocalIngress::default()),
        })
    }

    pub(crate) fn set_local_addresses(&self, ifindex: u32, cidrs: &[Ipv4Cidr], up: bool) {
        let mut ingress = self.local_ingress.lock();
        ingress.addresses.insert(ifindex, (up, cidrs.iter().map(|cidr| cidr.address()).collect()));
        if !up { ingress.packets.remove(&ifindex); }
    }

    pub(crate) fn forward_local_tcp(&self, incoming: u32, destination: Ipv4Address, packet: RxPacket<NetworkLayer>) -> Option<RxPacket<NetworkLayer>> {
        if destination.is_loopback() { return None; }
        let mut ingress = self.local_ingress.lock();
        let owner = ingress.addresses.iter().find_map(|(index, (up, addresses))|
            (*up && *index != incoming && addresses.contains(&destination)).then_some(*index));
        let Some(owner) = owner else { return Some(packet); };
        let queue = ingress.packets.entry(owner).or_default();
        if queue.len() < 64 { queue.push_back(packet); }
        drop(ingress);
        E::wake_forwarded_ip(owner);
        None
    }

    pub(crate) fn take_forwarded_tcp(&self, ifindex: u32) -> Option<RxPacket<NetworkLayer>> {
        self.local_ingress.lock().packets.get_mut(&ifindex)?.pop_front()
    }

    pub(crate) fn has_forwarded_tcp(&self, ifindex: u32) -> bool {
        self.local_ingress.lock().packets.get(&ifindex).is_some_and(|packets| !packets.is_empty())
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

    pub(crate) fn path_mtu(&self, ifindex: u32, destination: IpAddress, interface_mtu: usize) -> super::PathMtu {
        self.path_mtu_for_route(ifindex, destination, super::PathMtuRoute::Default, interface_mtu)
    }

    pub(crate) fn path_mtu_for_route(&self, ifindex: u32, destination: IpAddress, route: super::PathMtuRoute, interface_mtu: usize) -> super::PathMtu {
        let now = super::time::get_network_timestamp().total_millis();
        let mut entries = self.path_mtu.lock();
        entries.retain(|entry| entry.expires_at_ms > now);
        entries.iter().find(|entry| entry.ifindex == ifindex && entry.destination == destination && entry.route == route).map_or(
            super::PathMtu { mtu: interface_mtu, locked: false },
            |entry| super::PathMtu { mtu: entry.mtu.min(interface_mtu), locked: entry.locked },
        )
    }

    pub(crate) fn update_path_mtu_for_route(&self, ifindex: u32, destination: IpAddress, route: super::PathMtuRoute, advertised_mtu: usize) {
        let now = super::time::get_network_timestamp().total_millis();
        let locked = advertised_mtu < 552;
        let mtu = advertised_mtu.max(552);
        let mut entries = self.path_mtu.lock();
        entries.retain(|entry| entry.expires_at_ms > now);
        if let Some(entry) = entries.iter_mut().find(|entry| entry.ifindex == ifindex && entry.destination == destination && entry.route == route) {
            if !entry.locked && mtu <= entry.mtu {
                entry.mtu = mtu;
                entry.locked = locked;
                entry.expires_at_ms = now + 600_000;
            }
            return;
        }
        if entries.len() == 256 { entries.remove(0); }
        entries.push(PathMtuEntry { ifindex, destination, route, mtu, locked, expires_at_ms: now + 600_000 });
    }

    pub(crate) fn clear_path_mtu(&self, ifindex: u32) {
        self.path_mtu.lock().retain(|entry| entry.ifindex != ifindex);
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
    registry: Arc<NetworkRegistry<E>>,
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

    pub(crate) fn receive_endpoint(&self) -> IpEndpoint {
        self.registry.state.lock().bindings.get(&self.id)
            .map_or(self.endpoint, |binding| binding.endpoint)
    }

    pub(crate) fn set_receive_address(&self, address: IpAddress) {
        if let Some(binding) = self.registry.state.lock().bindings.get_mut(&self.id) {
            binding.endpoint.addr = address;
        }
    }

    pub fn device(&self) -> Option<u32> { self.device }

    pub(crate) fn same_reuse_port_group(&self, other: &Self) -> bool {
        self.reuse_port.load(Ordering::Acquire) && other.reuse_port.load(Ordering::Acquire)
            && self.owner.load(Ordering::Acquire) == other.owner.load(Ordering::Acquire)
            && self.receive_endpoint() == other.receive_endpoint() && self.device == other.device
    }

    pub(crate) fn registry(&self) -> &Arc<NetworkRegistry<E>> { &self.registry }

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

#[cfg(ktest)]
mod test {
    use ostd::prelude::ktest;
    use smoltcp::wire::Ipv4Address;
    use super::*;

    struct TestExt;
    struct TestSchedule;
    impl super::super::ScheduleNextPoll for TestSchedule {
        fn schedule_next_poll(&self, _ms: Option<u64>) {}
    }
    impl Ext for TestExt {
        type ScheduleNextPoll = TestSchedule;
        type TcpEventObserver = ();
        type UdpEventObserver = ();
        fn wall_time_ns() -> u64 { 0 }
    }

    #[ktest]
    fn forwarded_tcp_is_bounded_and_tracks_interface_addresses() {
        let registry = NetworkRegistry::<TestExt>::new();
        let destination = Ipv4Address::new(192, 0, 2, 100);
        let loopback = Ipv4Address::new(127, 0, 0, 1);
        registry.set_local_addresses(7, &[Ipv4Cidr::new(destination, 24)], true);
        registry.set_local_addresses(1, &[Ipv4Cidr::new(loopback, 8)], true);
        let packet = || crate::packet::FreshTxPacket::<NetworkLayer>::alloc(0).unwrap().to_builder().build().to_rx_packet().unwrap();
        assert!(registry.forward_local_tcp(8, loopback, packet()).is_none());
        assert!(!registry.has_forwarded_tcp(1));
        for _ in 0..65 { assert!(registry.forward_local_tcp(8, destination, packet()).is_none()); }
        for _ in 0..64 { assert!(registry.take_forwarded_tcp(7).is_some()); }
        assert!(!registry.has_forwarded_tcp(7));
        assert!(registry.forward_local_tcp(8, destination, packet()).is_none());
        registry.set_local_addresses(7, &[Ipv4Cidr::new(destination, 24)], false);
        assert!(!registry.has_forwarded_tcp(7));
        assert!(registry.forward_local_tcp(8, destination, packet()).is_some());
    }

    #[ktest]
    fn path_mtu_is_specific_to_the_selected_route() {
        let registry = NetworkRegistry::<TestExt>::new();
        let destination = IpAddress::Ipv4(Ipv4Address::new(198, 51, 100, 9));
        let main = super::super::PathMtuRoute::Default;
        let alternate = super::super::PathMtuRoute::Table {
            table: 100, gateway: Some(Ipv4Address::new(192, 0, 2, 2)),
        };
        registry.update_path_mtu_for_route(7, destination, main, 600);
        assert_eq!(registry.path_mtu_for_route(7, destination, main, 1500).mtu, 600);
        assert_eq!(registry.path_mtu_for_route(7, destination, alternate, 1500).mtu, 1500);
        registry.update_path_mtu_for_route(7, destination, alternate, 800);
        assert_eq!(registry.path_mtu_for_route(7, destination, main, 1500).mtu, 600);
        assert_eq!(registry.path_mtu_for_route(7, destination, alternate, 1500).mtu, 800);
    }

    #[ktest]
    fn path_mtu_limits_are_bounded_and_cleared_per_interface() {
        let registry = NetworkRegistry::<TestExt>::new();
        for index in 0..257 {
            let destination = IpAddress::Ipv4(Ipv4Address::new(10, (index >> 8) as u8, index as u8, 1));
            registry.update_path_mtu_for_route(7, destination, super::super::PathMtuRoute::Default, 600);
        }
        let first = IpAddress::Ipv4(Ipv4Address::new(10, 0, 0, 1));
        let last = IpAddress::Ipv4(Ipv4Address::new(10, 1, 0, 1));
        assert_eq!(registry.path_mtu(7, first, 1500).mtu, 1500);
        assert_eq!(registry.path_mtu(7, last, 1500).mtu, 600);
        registry.update_path_mtu_for_route(8, last, super::super::PathMtuRoute::Default, 700);
        registry.clear_path_mtu(7);
        assert_eq!(registry.path_mtu(7, last, 1500).mtu, 1500);
        assert_eq!(registry.path_mtu(8, last, 1500).mtu, 700);
        registry.path_mtu.lock()[0].expires_at_ms = 0;
        assert_eq!(registry.path_mtu(8, last, 1500).mtu, 1500);
    }
}
