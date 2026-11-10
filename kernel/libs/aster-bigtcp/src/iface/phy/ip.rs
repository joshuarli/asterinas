// SPDX-License-Identifier: MPL-2.0

use alloc::{collections::vec_deque::VecDeque, sync::Arc, vec, vec::Vec};

use aster_softirq::BottomHalfDisabled;

use ostd::{
    mm::{Infallible, VmReader, VmWriter},
    sync::SpinLock,
};

use smoltcp::{
    iface::{Config, Context},
    wire::{self, EthernetAddress, Ipv4Cidr, Ipv6Cidr},
};

use crate::{
    device::{AnyNetworkDevice, WithDevice, new_interface},
    errors::LinkSendError,
    ext::Ext,
    iface::{
        Iface, InterfaceName, LinkTap, NetworkRegistry,
        common::{
            IfaceCommon, InterfaceFlags, InterfaceType, PhyProcessResult, PollPhy, TxPacketWithDst,
            link_packet_from_bytes,
        },
        iface::internal::IfaceInternal,
        time::get_network_timestamp,
    },
    packet::{FreshTxPacket, LinkLayer, RxPacket, TxPacket},
};

pub struct IpIface<D, E: Ext> {
    driver: D,
    common: IfaceCommon<E>,
    looped: SpinLock<VecDeque<RxPacket<LinkLayer>>, BottomHalfDisabled>,
}

impl<D: WithDevice, E: Ext> IpIface<D, E> {
    // TODO: Support interfaces with multiple IPv4/IPv6 addresses or without IPv4 addresses.
    pub fn new(
        driver: D,
        ip_cidr: Ipv4Cidr,
        ipv6_cidr: Option<Ipv6Cidr>,
        name: InterfaceName,
        sched_poll: E::ScheduleNextPoll,
        type_: InterfaceType,
        flags: InterfaceFlags,
        network: Arc<NetworkRegistry<E>>,
    ) -> Arc<Self> {
        let interface = driver.with(|device| {
            let config = Config::new(wire::HardwareAddress::Ip);
            let now = get_network_timestamp();

            let mut interface = new_interface(config, device.capabilities(), now);
            interface.update_ip_addrs(|ip_addrs| {
                debug_assert!(ip_addrs.is_empty());
                ip_addrs.push(wire::IpCidr::Ipv4(ip_cidr)).unwrap();
                if let Some(ipv6_cidr) = ipv6_cidr {
                    ip_addrs.push(wire::IpCidr::Ipv6(ipv6_cidr)).unwrap();
                }
            });
            interface
        });

        let common = IfaceCommon::new(name, type_, flags, interface, sched_poll, network);

        Arc::new(Self {
            driver,
            common,
            looped: SpinLock::new(VecDeque::new()),
        })
    }
}

impl<D, E: Ext> IfaceInternal<E> for IpIface<D, E> {
    fn common(&self) -> &IfaceCommon<E> {
        &self.common
    }
}

impl<D: WithDevice + 'static, E: Ext> Iface<E> for IpIface<D, E> {
    fn ethernet_addr(&self) -> Option<EthernetAddress> {
        None
    }

    fn poll(&self) {
        self.common.poll(&self.driver, self);
    }

    fn mtu(&self) -> usize {
        self.driver.with(|device| device.mtu())
    }

    fn flush_neighbors(&self) {}

    fn send_link_frame(
        &self,
        frame: &[u8],
        origin: Option<&Arc<dyn LinkTap>>,
    ) -> Result<(), LinkSendError> {
        const HEADER_LEN: usize = 14;

        self.common.ensure_up()?;
        if frame.len() <= HEADER_LEN {
            return Err(LinkSendError::TooShort);
        }
        let payload = &frame[HEADER_LEN..];
        let ethertype = u16::from_be_bytes([frame[HEADER_LEN - 2], frame[HEADER_LEN - 1]]);
        if ethertype_of_ip_packet(payload[0]) != Some(ethertype) {
            return Err(LinkSendError::UnsupportedProtocol);
        }
        if payload.len() > self.driver.with(|device| device.mtu()) {
            return Err(LinkSendError::TooLong);
        }

        let packet = link_packet_from_bytes::<D::Device>(payload)?;
        self.common.tap_outgoing(self, origin, &packet);
        let packet = packet.to_rx_packet().ok_or(LinkSendError::NoMemory)?;
        self.common.record_tx_frame(self, packet.len());
        self.looped.lock().push_back(packet);
        Ok(())
    }
}

impl<D: WithDevice + 'static, E: Ext> PollPhy for IpIface<D, E> {
    fn is_loopback(&self) -> bool {
        self.common.type_() == InterfaceType::LOOPBACK
    }
    fn process(
        &self,
        packet: RxPacket<LinkLayer>,
        _iface_cx: &mut Context,
        _ipv4_cidrs: &[Ipv4Cidr],
    ) -> Option<PhyProcessResult> {
        Some(PhyProcessResult::Ip(packet.peel(0)))
    }

    fn dispatch(
        &self,
        packet: TxPacketWithDst,
        _iface_cx: &mut Context,
        _ipv4_cidrs: &[Ipv4Cidr],
    ) -> Option<TxPacket<LinkLayer>> {
        Some(packet.packet.pack(0))
    }

    fn take_neighbor_frame(
        &self,
        _iface_cx: &mut Context,
        _ipv4_cidrs: &[Ipv4Cidr],
    ) -> Option<TxPacket<LinkLayer>> {
        None
    }

    fn next_neighbor_poll_ms(&self) -> Option<u64> {
        None
    }

    fn alloc_tx_buffer(&self, payload_len: usize) -> Result<FreshTxPacket, ostd::Error> {
        D::Device::alloc_tx_buffer(payload_len)
    }

    fn hardware_addr(&self) -> [u8; 6] {
        [0; 6]
    }

    fn peek_ethertype(&self, mut frame: VmReader<'_, Infallible>) -> Option<u16> {
        ethertype_of_ip_packet(frame.read_val::<u8>().ok()?)
    }

    fn take_looped_frame(&self) -> Option<RxPacket<LinkLayer>> {
        self.looped.lock().pop_front()
    }

    fn copy_ethernet_frame(&self, mut frame: VmReader<'_, Infallible>) -> Vec<u8> {
        const HEADER_LEN: usize = 14;

        let mut bytes = vec![0u8; HEADER_LEN + frame.remain()];
        frame.read(&mut VmWriter::from(&mut bytes[HEADER_LEN..]));
        let ethertype = ethertype_of_ip_packet(bytes[HEADER_LEN]).unwrap_or(0);
        bytes[HEADER_LEN - 2..HEADER_LEN].copy_from_slice(&ethertype.to_be_bytes());
        bytes
    }
}

fn ethertype_of_ip_packet(first_byte: u8) -> Option<u16> {
    const ETHERTYPE_IPV4: u16 = 0x0800;
    const ETHERTYPE_IPV6: u16 = 0x86dd;

    match first_byte >> 4 {
        4 => Some(ETHERTYPE_IPV4),
        6 => Some(ETHERTYPE_IPV6),
        _ => None,
    }
}
