// SPDX-License-Identifier: MPL-2.0

use alloc::format;
use core::slice::Iter;

use aster_bigtcp::{
    device::{AnyNetworkDevice, WithDevice},
    iface::{InterfaceFlags, InterfaceName, InterfaceType, NetworkRegistry},
};
use aster_softirq::BottomHalfDisabled;
use spin::Once;

use super::{Iface, poll::poll_ifaces};
use crate::{net::iface::sched::PollScheduler, prelude::*};

struct NetworkStack {
    ifaces: Vec<Arc<Iface>>,
    network: Arc<NetworkRegistry<super::ext::BigtcpExt>>,
    devices: Vec<(String, Arc<Iface>)>,
}

static NETWORK: Once<NetworkStack> = Once::new();

pub(in crate::net) fn iter_all_ifaces() -> Iter<'static, Arc<Iface>> {
    NETWORK.get().unwrap().ifaces.iter()
}

pub(in crate::net) fn network_registry() -> &'static Arc<NetworkRegistry<super::ext::BigtcpExt>> {
    &NETWORK.get().unwrap().network
}

const VIRTIO_DEVICE_NAME: &str = aster_virtio::device::network::DEVICE_NAME;

pub(in crate::net) fn init() {
    NETWORK.call_once(|| {
        let network = NetworkRegistry::new();
        let mut ifaces = Vec::new();
        ifaces.push(new_loopback(network.clone()));
        let mut devices = Vec::new();
        for (name, device) in aster_network::all_devices() {
            if !name.starts_with(VIRTIO_DEVICE_NAME) { continue; }
            let iface = new_virtio(device, devices.len(), network.clone());
            ifaces.push(iface.clone());
            devices.push((name, iface));
        }
        NetworkStack { ifaces, network, devices }
    });

    for (name, iface) in &NETWORK.get().unwrap().devices {
        let rx_iface = iface.clone();
        let tx_iface = iface.clone();
        aster_network::register_recv_callback(name, move || rx_iface.poll());
        aster_network::register_send_callback(name, move || tx_iface.poll());
    }

    super::config::init();

    poll_ifaces();
}

fn new_loopback(network: Arc<NetworkRegistry<super::ext::BigtcpExt>>) -> Arc<Iface> {
    use aster_bigtcp::{
        device::Loopback,
        iface::IpIface,
        wire::{Ipv4Address, Ipv4Cidr, Ipv6Address, Ipv6Cidr},
    };

    const LOOPBACK_ADDRESS: Ipv4Address = Ipv4Address::new(127, 0, 0, 1);
    const LOOPBACK_ADDRESS_PREFIX_LEN: u8 = 8; // mask: 255.0.0.0
    const LOOPBACK_IPV6_ADDRESS: Ipv6Address = Ipv6Address::new(0, 0, 0, 0, 0, 0, 0, 1);
    const LOOPBACK_IPV6_PREFIX_LEN: u8 = 128;

    struct Wrapper(Mutex<Loopback>);

    impl WithDevice for Wrapper {
        type Device = Loopback;

        fn with<F, R>(&self, f: F) -> R
        where
            F: FnOnce(&mut dyn AnyNetworkDevice) -> R,
        {
            let mut device = self.0.lock();
            f(&mut *device)
        }
    }

    // FIXME: These flags are currently hardcoded.
    // In the future, we should set appropriate values.
    let flags = InterfaceFlags::UP
        | InterfaceFlags::LOOPBACK
        | InterfaceFlags::RUNNING
        | InterfaceFlags::LOWER_UP;

    IpIface::new(
        Wrapper(Mutex::new(Loopback::new())),
        Ipv4Cidr::new(LOOPBACK_ADDRESS, LOOPBACK_ADDRESS_PREFIX_LEN),
        Some(Ipv6Cidr::new(
            LOOPBACK_IPV6_ADDRESS,
            LOOPBACK_IPV6_PREFIX_LEN,
        )),
        InterfaceName::from_str_truncated("lo"),
        PollScheduler::new(),
        InterfaceType::LOOPBACK,
        flags,
        network,
    ) as Arc<Iface>
}

fn new_virtio(
    virtio_net: Arc<SpinLock<dyn AnyNetworkDevice, BottomHalfDisabled>>,
    index: usize,
    network: Arc<NetworkRegistry<super::ext::BigtcpExt>>,
) -> Arc<Iface> {
    use aster_bigtcp::iface::EtherIface;

    let ether_addr = virtio_net.lock().mac_addr();

    struct Wrapper(Arc<SpinLock<dyn AnyNetworkDevice, BottomHalfDisabled>>);

    impl WithDevice for Wrapper {
        type Device = aster_virtio::device::network::device::NetworkDevice;

        fn with<F, R>(&self, f: F) -> R
        where
            F: FnOnce(&mut dyn AnyNetworkDevice) -> R,
        {
            let mut device = self.0.lock();
            f(&mut *device)
        }
    }

    // Like a Linux Ethernet device, the interface starts down and without any address or route.
    // User space brings it up and configures it.
    let flags = InterfaceFlags::BROADCAST | InterfaceFlags::MULTICAST;

    EtherIface::new(
        Wrapper(virtio_net),
        ether_addr,
        InterfaceName::from_str_truncated(&format!("eth{index}")),
        PollScheduler::new(),
        flags,
        network,
    )
}
