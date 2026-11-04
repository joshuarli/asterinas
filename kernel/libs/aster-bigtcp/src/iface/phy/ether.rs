// SPDX-License-Identifier: MPL-2.0

use alloc::{collections::VecDeque, sync::Arc, vec, vec::Vec};

use aster_softirq::BottomHalfDisabled;
use ostd::{
    mm::{Infallible, VmReader, VmWriter},
    sync::SpinLock,
};
use smoltcp::{
    iface::{Config, Context},
    wire::{
        self, ArpOperation, ArpRepr, EthernetAddress, EthernetProtocol, EthernetRepr, IpAddress,
        IPV4_HEADER_LEN, IPV4_MIN_MTU,
        Ipv4Address, Ipv4AddressExt, Ipv4Cidr,
    },
};

use crate::{
    device::{AnyNetworkDevice, WithDevice, new_interface},
    errors::LinkSendError,
    ext::Ext,
    iface::{
        Iface, InterfaceFlags, InterfaceName, LinkTap, NetworkRegistry,
        common::{
            IfaceCommon, InterfaceType, PhyProcessResult, PollPhy, TxPacketWithDst,
            link_packet_from_bytes,
        },
        iface::internal::IfaceInternal,
        time::get_network_timestamp,
        phy::neighbors::{Due, Neighbors, Queued},
        wire::{arp, ether, icmp},
    },
    packet::{FreshTxPacket, LinkLayer, RxPacket, TransportLayer, TxPacket},
    socket::IpNextHop,
};

pub struct EtherIface<D, E: Ext> {
    driver: D,
    common: IfaceCommon<E>,
    ether_addr: EthernetAddress,
    neighbors: SpinLock<Neighbors<TxPacketWithDst>, BottomHalfDisabled>,
    released: SpinLock<VecDeque<TxPacket<LinkLayer>>, BottomHalfDisabled>,
}

impl<D: WithDevice, E: Ext> EtherIface<D, E> {
    pub fn new(
        driver: D,
        ether_addr: EthernetAddress,
        name: InterfaceName,
        sched_poll: E::ScheduleNextPoll,
        flags: InterfaceFlags,
        network: Arc<NetworkRegistry<E>>,
    ) -> Arc<Self> {
        let interface = driver.with(|device| {
            let config = Config::new(wire::HardwareAddress::Ethernet(ether_addr));
            let now = get_network_timestamp();

            new_interface(config, device.capabilities(), now)
        });

        let common = IfaceCommon::new(name, InterfaceType::ETHER, flags, interface, sched_poll, network);

        Arc::new(Self {
            driver,
            common,
            ether_addr,
            neighbors: SpinLock::new(Neighbors::new()),
            released: SpinLock::new(VecDeque::new()),
        })
    }
}

impl<D, E: Ext> IfaceInternal<E> for EtherIface<D, E> {
    fn common(&self) -> &IfaceCommon<E> {
        &self.common
    }
}

impl<D: WithDevice + 'static, E: Ext> Iface<E> for EtherIface<D, E> {
    fn ethernet_addr(&self) -> Option<EthernetAddress> {
        Some(self.ether_addr)
    }

    fn poll(&self) {
        self.common.poll(&self.driver, self);
    }

    fn mtu(&self) -> usize {
        self.driver.with(|device| device.mtu())
    }

    fn flush_neighbors(&self) {
        self.neighbors.lock().clear();
        self.released.lock().clear();
    }

    fn send_link_frame(
        &self,
        frame: &[u8],
        origin: Option<&Arc<dyn LinkTap>>,
    ) -> Result<(), LinkSendError> {
        const HEADER_LEN: usize = 14;

        self.common.ensure_up()?;
        if frame.len() < HEADER_LEN {
            return Err(LinkSendError::TooShort);
        }
        if frame.len() > self.driver.with(|device| device.mtu()) + HEADER_LEN {
            return Err(LinkSendError::TooLong);
        }

        let packet = link_packet_from_bytes::<D::Device>(frame)?;
        self.driver.with(|device| {
            if !device.can_send() {
                return Err(LinkSendError::Busy);
            }
            self.common.tap_outgoing(self, origin, &packet);
            device.send(packet).map_err(|_| LinkSendError::Busy)
        })
    }
}

impl<D: WithDevice + 'static, E: Ext> PollPhy for EtherIface<D, E> {
    fn process(
        &self,
        packet: RxPacket<LinkLayer>,
        iface_cx: &mut Context,
        ipv4_cidrs: &[Ipv4Cidr],
    ) -> Option<PhyProcessResult> {
        // Parse the Ethernet header. Ignore the packet if the header is ill-formed.
        let (packet, repr) = ether::parse(packet)?;

        // Ignore the Ethernet frame if it is not sent to us.
        if !repr.dst_addr.is_broadcast() && repr.dst_addr != self.ether_addr {
            return None;
        }

        // Ignore the Ethernet frame if the protocol is not supported.
        match repr.ethertype {
            EthernetProtocol::Ipv4 => Some(PhyProcessResult::Ipv4(packet)),
            EthernetProtocol::Ipv6 => Some(PhyProcessResult::Ipv6(packet)),
            EthernetProtocol::Arp => {
                let (_, arp_repr) = arp::parse(packet)?;
                let reply = self.process_arp(&arp_repr, iface_cx, ipv4_cidrs)?;
                match self.alloc_tx_buffer(0) {
                    Ok(buffer) => Self::emit_arp(&reply, buffer).map(PhyProcessResult::Tx),
                    Err(err) => {
                        ostd::error!("failed to allocate a network packet: {:?}", err);
                        None
                    }
                }
            }
            _ => None,
        }
    }

    fn dispatch(
        &self,
        packet: TxPacketWithDst,
        iface_cx: &mut Context,
        ipv4_cidrs: &[Ipv4Cidr],
    ) -> Option<TxPacket<LinkLayer>> {
        let route = match packet.next_hop {
            IpNextHop::Routed => iface_cx.route(&packet.dst_addr, iface_cx.now()),
            IpNextHop::Direct => Some(packet.dst_addr),
            IpNextHop::Gateway(gateway) => Some(IpAddress::Ipv4(gateway)),
        };
        let next_hop_ip = match route {
            Some(IpAddress::Ipv4(next_hop_ip)) => next_hop_ip,
            Some(IpAddress::Ipv6(_)) => {
                // FIXME: Currently, we drop outbound IPv6 packets because neighbor discovery is not
                // implemented and we have no way to resolve the next-hop link-layer address.
                ostd::debug!("IPv6 neighbor discovery is not implemented for Ethernet interfaces");
                return None;
            }
            None => return None,
        };

        let next_hop_ether = if next_hop_ip.is_broadcast() {
            EthernetAddress::BROADCAST
        } else if let Some(next_hop_ether) = self.neighbors.lock().resolved(next_hop_ip) {
            next_hop_ether
        } else {
            let len = packet.packet.len();
            let now_ms = iface_cx.now().total_millis();
            let queued = self
                .neighbors
                .lock()
                .queue(next_hop_ip, packet, len, now_ms);
            return match queued {
                Queued::ProbeNow => self.arp_request(next_hop_ip, ipv4_cidrs),
                Queued::Waiting | Queued::Dropped => None,
            };
        };

        Some(ether::emit(
            packet.packet,
            &EthernetRepr {
                src_addr: self.ether_addr,
                dst_addr: next_hop_ether,
                ethertype: EthernetProtocol::Ipv4,
            },
        ))
    }

    fn take_neighbor_frame(
        &self,
        iface_cx: &mut Context,
        ipv4_cidrs: &[Ipv4Cidr],
    ) -> Option<TxPacket<LinkLayer>> {
        if let Some(frame) = self.released.lock().pop_front() {
            return Some(frame);
        }

        let now_ms = iface_cx.now().total_millis();
        loop {
            let due = self.neighbors.lock().due(now_ms)?;
            match due {
                Due::Probe(address) => {
                    if let Some(frame) = self.arp_request(address, ipv4_cidrs) {
                        return Some(frame);
                    }
                }
                Due::Failed(address, packets) => {
                    for packet in &packets {
                        if let Some((reporter, destination)) = &packet.failure {
                            let mut bytes = vec![0; packet.packet.len()];
                            packet.packet.reader().read(&mut VmWriter::from(bytes.as_mut_slice()));
                            if let Some((offender, payload)) = queued_udp_payload(&bytes) {
                                reporter.report(*destination, offender.into(), payload.to_vec(), icmp::reply_tos(bytes[1]));
                            }
                        }
                    }
                    ostd::debug!(
                        "{} packets for the unreachable neighbor {} were dropped",
                        packets.len(),
                        address
                    );
                }
            }
        }
    }

    fn next_neighbor_poll_ms(&self) -> Option<u64> {
        let deadline = self.neighbors.lock().next_deadline_ms()?;
        Some(deadline.max(0) as u64)
    }

    fn alloc_tx_buffer(&self, payload_len: usize) -> Result<FreshTxPacket, ostd::Error> {
        D::Device::alloc_tx_buffer(payload_len)
    }

    fn hardware_addr(&self) -> [u8; 6] {
        self.ether_addr.0
    }

    fn peek_ethertype(&self, frame: VmReader<'_, Infallible>) -> Option<u16> {
        ether::peek_ethertype(frame)
    }

    fn copy_ethernet_frame(&self, mut frame: VmReader<'_, Infallible>) -> Vec<u8> {
        let mut bytes = vec![0u8; frame.remain()];
        frame.read(&mut VmWriter::from(bytes.as_mut_slice()));
        bytes
    }

    fn take_looped_frame(&self) -> Option<RxPacket<LinkLayer>> {
        None
    }
}

impl<D: WithDevice + 'static, E: Ext> EtherIface<D, E> {
    fn arp_request(
        &self,
        target: Ipv4Address,
        ipv4_cidrs: &[Ipv4Cidr],
    ) -> Option<TxPacket<LinkLayer>> {
        let buffer = match self.alloc_tx_buffer(0) {
            Ok(buffer) => buffer,
            Err(err) => {
                ostd::error!("failed to allocate a network packet: {:?}", err);
                return None;
            }
        };
        Self::emit_arp(
            &ArpRepr::EthernetIpv4 {
                operation: ArpOperation::Request,
                source_hardware_addr: self.ether_addr,
                source_protocol_addr: arp_source_address(ipv4_cidrs, target),
                target_hardware_addr: EthernetAddress::BROADCAST,
                target_protocol_addr: target,
            },
            buffer,
        )
    }
}

/// Picks the address that asks for `target`: the one on the same network, else the first one.
fn arp_source_address(ipv4_cidrs: &[Ipv4Cidr], target: Ipv4Address) -> Ipv4Address {
    ipv4_cidrs
        .iter()
        .find(|cidr| cidr.contains_addr(&target))
        .or(ipv4_cidrs.first())
        .map_or(Ipv4Address::UNSPECIFIED, |cidr| cidr.address())
}

impl<D, E: Ext> EtherIface<D, E> {
    fn process_arp(
        &self,
        arp_repr: &ArpRepr,
        iface_cx: &mut Context,
        ipv4_cidrs: &[Ipv4Cidr],
    ) -> Option<ArpRepr> {
        match arp_repr {
            ArpRepr::EthernetIpv4 {
                operation: ArpOperation::Reply,
                source_hardware_addr,
                source_protocol_addr,
                ..
            } => {
                // Ignore the ARP packet if the source addresses are not unicast or not local.
                if !source_hardware_addr.is_unicast()
                    || !iface_cx.in_same_network(&IpAddress::Ipv4(*source_protocol_addr))
                {
                    return None;
                }

                // Insert the mapping between the Ethernet address and the IP address, and send the
                // packets that waited for it.
                //
                // TODO: Remove the mapping if it expires.
                let waiting = self
                    .neighbors
                    .lock()
                    .learn(*source_protocol_addr, *source_hardware_addr);
                let mut released = self.released.lock();
                for packet in waiting {
                    released.push_back(ether::emit(
                        packet.packet,
                        &EthernetRepr {
                            src_addr: self.ether_addr,
                            dst_addr: *source_hardware_addr,
                            ethertype: EthernetProtocol::Ipv4,
                        },
                    ));
                }

                None
            }
            ArpRepr::EthernetIpv4 {
                operation: ArpOperation::Request,
                source_hardware_addr,
                source_protocol_addr,
                target_protocol_addr,
                ..
            } => {
                // Ignore the ARP packet if the source addresses are not unicast.
                if !source_hardware_addr.is_unicast() || !source_protocol_addr.x_is_unicast() {
                    return None;
                }

                // Ignore the ARP packet if we do not own the target address.
                if !ipv4_cidrs
                    .iter()
                    .any(|cidr| cidr.address() == *target_protocol_addr)
                {
                    return None;
                }

                Some(ArpRepr::EthernetIpv4 {
                    operation: ArpOperation::Reply,
                    source_hardware_addr: self.ether_addr,
                    source_protocol_addr: *target_protocol_addr,
                    target_hardware_addr: *source_hardware_addr,
                    target_protocol_addr: *source_protocol_addr,
                })
            }
            _ => None,
        }
    }

    fn emit_arp(arp_repr: &ArpRepr, packet: FreshTxPacket) -> Option<TxPacket<LinkLayer>> {
        let ether_repr = match arp_repr {
            ArpRepr::EthernetIpv4 {
                source_hardware_addr,
                target_hardware_addr,
                ..
            } => EthernetRepr {
                src_addr: *source_hardware_addr,
                dst_addr: *target_hardware_addr,
                ethertype: EthernetProtocol::Arp,
            },
            _ => return None,
        };

        let packet = packet.to_builder_at_layer::<TransportLayer>().build();
        let packet = arp::emit(packet, arp_repr);
        Some(ether::emit(packet, &ether_repr))
    }
}

fn queued_udp_payload(packet: &[u8]) -> Option<(Ipv4Address, &[u8])> {
    if packet.len() < 28 || packet[0] >> 4 != 4 || packet[9] != 17 {
        return None;
    }
    let header_len = usize::from(packet[0] & 15) * 4;
    if header_len < 20 || packet.len() < header_len + 8 {
        return None;
    }
    let fragment = u16::from_be_bytes([packet[6], packet[7]]);
    if fragment & 0x1fff != 0 {
        return None;
    }
    let udp = &packet[header_len..];
    let len = usize::from(u16::from_be_bytes([udp[4], udp[5]]));
    if len < 8 || len > udp.len() && fragment & 0x2000 == 0 {
        return None;
    }
    let quote_len = IPV4_MIN_MTU - IPV4_HEADER_LEN - icmp::HEADER_LEN - header_len;
    let end = len.min(udp.len()).min(quote_len);
    Some((Ipv4Address::new(packet[12], packet[13], packet[14], packet[15]), &udp[8..end]))
}
