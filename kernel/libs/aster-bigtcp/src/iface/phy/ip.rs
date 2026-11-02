// SPDX-License-Identifier: MPL-2.0

use alloc::{sync::Arc, vec, vec::Vec};

use ostd::mm::{Infallible, VmReader, VmWriter};

use smoltcp::{
    iface::{Config, Context},
    wire::{self, EthernetAddress, Ipv4Cidr, Ipv6Cidr},
};

use crate::{
    device::{AnyNetworkDevice, WithDevice, new_interface},
    ext::Ext,
    iface::{
        Iface, InterfaceName,
        common::{
            IfaceCommon, InterfaceFlags, InterfaceType, PhyProcessResult, PollPhy, TxPacketWithDst,
        },
        iface::internal::IfaceInternal,
        time::get_network_timestamp,
    },
    packet::{FreshTxPacket, LinkLayer, RxPacket, TxPacket},
};

pub struct IpIface<D, E: Ext> {
    driver: D,
    common: IfaceCommon<E>,
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

        let common = IfaceCommon::new(name, type_, flags, interface, sched_poll);

        Arc::new(Self { driver, common })
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
}

impl<D: WithDevice + 'static, E: Ext> PollPhy for IpIface<D, E> {
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

    fn alloc_tx_buffer(&self, payload_len: usize) -> Result<FreshTxPacket, ostd::Error> {
        D::Device::alloc_tx_buffer(payload_len)
    }

    fn hardware_addr(&self) -> [u8; 6] {
        [0; 6]
    }

    fn peek_ethertype(&self, mut frame: VmReader<'_, Infallible>) -> Option<u16> {
        ethertype_of_ip_packet(frame.read_val::<u8>().ok()?)
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
