// SPDX-License-Identifier: MPL-2.0

use alloc::{sync::Arc, vec::Vec};

use aster_softirq::BottomHalfDisabled;
use ostd::{mm::{Infallible, VmReader, VmWriter}, sync::SpinLock};
use alloc::collections::VecDeque;
use smoltcp::{
    storage::SliceLike,
    wire::{
        IPV4_HEADER_LEN, IPV4_MIN_MTU, Icmpv4DstUnreachable, IpAddress, IpProtocol, IpRepr,
        Ipv4Address, Ipv4Repr, TcpControl, TcpRepr, UDP_HEADER_LEN, UdpRepr,
    },
};

use super::{
    common::{PhyProcessResult, PollPhy, TxPacketWithDst},
    packet_slice::PacketSlice,
    poll_iface::PollableIfaceMut,
    tap::{FrameDirection, LinkTaps},
    wire::{
        icmp,
        ip::{self, IpReprWithLen},
        tcp, udp,
    },
};
use crate::{
    device::{AnyNetworkDevice, NetError},
    ext::Ext,
    iface::poll_iface::IsUnicast,
    packet::{ApplicationLayer, FreshTxPacket, LinkLayer, NetworkLayer, RxPacket, TransportLayer, TxPacket},
    socket::{TcpConnectionBg, TcpProcessResult, UdpError, UdpErrorOrigin, UdpFragmentation, UdpIpv4Options, IpNextHop, UdpSocketBg},
    socket_table::{ConnectionKey, ListenerKey, SocketTable, hash_local_remote},
};

fn send_frame(
    device: &mut dyn AnyNetworkDevice,
    phy: &dyn PollPhy,
    taps: &LinkTaps,
    packet: TxPacket<LinkLayer>,
) -> Result<(), NetError> {
    taps.deliver(phy, FrameDirection::Outgoing, None, || packet.reader());
    device.send(packet)
}

pub(super) struct PollContext<'a, E: Ext> {
    iface: PollableIfaceMut<'a, E>,
    sockets: &'a SocketTable<E>,
    udp_sockets: &'a [Arc<UdpSocketBg<E>>],
    udp_registry: &'a super::UdpRegistry<E>,
    ip_taps: &'a super::ip_tap::IpTaps,
    raw_ip_tx: &'a SpinLock<VecDeque<TxPacketWithDst>, BottomHalfDisabled>,
    ifindex: u32,
    actions: &'a mut Vec<SocketTableAction<E>>,
}

/// Socket table actions such as adding or removing TCP connections.
///
/// Note that they must be performed in order. This is because the same connection key can occur
/// multiple times, but with different types of operations (e.g., add or remove).
pub(super) enum SocketTableAction<E: Ext> {
    AddTcpConn(Arc<TcpConnectionBg<E>>),
    DelTcpConn(ConnectionKey),
}

impl<'a, E: Ext> PollContext<'a, E> {
    pub(super) fn new(
        iface: PollableIfaceMut<'a, E>,
        sockets: &'a SocketTable<E>,
        udp_sockets: &'a [Arc<UdpSocketBg<E>>],
        udp_registry: &'a super::UdpRegistry<E>,
        ip_taps: &'a super::ip_tap::IpTaps,
        raw_ip_tx: &'a SpinLock<VecDeque<TxPacketWithDst>, BottomHalfDisabled>,
        ifindex: u32,
        actions: &'a mut Vec<SocketTableAction<E>>,
    ) -> Self {
        Self {
            iface,
            sockets,
            udp_sockets,
            udp_registry,
            ip_taps,
            raw_ip_tx,
            ifindex,
            actions,
        }
    }
}

impl<E: Ext> PollContext<'_, E> {
    pub(super) fn poll_ingress(
        &mut self,
        device: &mut dyn AnyNetworkDevice,
        phy: &dyn PollPhy,
        taps: &LinkTaps,
    ) {
        let ipv4_cidrs = self.iface.ipv4_cidrs();
        loop {
            let rx_packet = match device.receive() {
                Ok(packet) => packet,
                Err(NetError::NotReady) => match phy.take_looped_frame() {
                    Some(packet) => packet,
                    None => break,
                },
                Err(err) => {
                    ostd::error!("failed to receive a network packet: {:?}", err);
                    break;
                }
            };

            taps.deliver(phy, FrameDirection::Incoming, None, || rx_packet.reader());

            let Some(processed) = phy.process(rx_packet, self.iface.context_mut(), ipv4_cidrs) else {
                continue;
            };
            let (packet, ip_version) = match processed {
                PhyProcessResult::Ip(packet) => (packet, None),
                PhyProcessResult::Ipv4(packet) => (packet, Some(ip::Version::V4)),
                PhyProcessResult::Ipv6(packet) => (packet, Some(ip::Version::V6)),
                PhyProcessResult::Tx(packet) => {
                    if let Err(err) = send_frame(device, phy, taps, packet) {
                        ostd::error!("failed to send a network packet: {:?}", err);
                    }
                    continue;
                }
            };

            if let Some(reply) = self.parse_and_process_ip(phy, packet, ip_version, device.mtu())
                && let Some(tx_packet) = phy.dispatch(reply, self.iface.context_mut(), ipv4_cidrs)
                && let Err(err) = send_frame(device, phy, taps, tx_packet)
            {
                ostd::error!("failed to send a network packet: {:?}", err);
            }
        }
    }

    fn parse_and_process_ip(
        &mut self,
        phy: &dyn PollPhy,
        packet: RxPacket<NetworkLayer>,
        ip_version: Option<ip::Version>,
        mtu: usize,
    ) -> Option<TxPacketWithDst> {
        // Parse the IP header. Ignore the packet if the header is ill-formed.
        let checksum_caps = self.iface.context().checksum_caps();
        let now = self.iface.context().now().total_millis();
        let packet = if ip_version != Some(ip::Version::V6) {
            self.iface.reassemble(packet, now, checksum_caps.ipv4.rx())?
        } else {
            packet
        };
        let (packet, ip_repr) = ip::parse(packet, ip_version, checksum_caps.ipv4.rx())?;

        let can_process = {
            let dst_addr = ip_repr.inner.dst_addr();
            self.iface.context().is_broadcast(&dst_addr) || self.iface.is_unicast_local(dst_addr)
        };
        if !can_process {
            return self.generate_icmp_unreachable(
                phy,
                &ip_repr.inner,
                packet.reader_with_header(ip_repr.header_len),
                Icmpv4DstUnreachable::HostUnreachable,
                ip_repr.tos,
            );
        }

        self.ip_taps.deliver(self.ifindex, ip_repr.inner.next_header().into(), packet.reader_with_header(ip_repr.header_len));

        match ip_repr.inner.next_header() {
            IpProtocol::Tcp => {
                self.parse_and_process_tcp(phy, &ip_repr.inner, packet, checksum_caps.tcp.rx())
            }
            IpProtocol::Udp => {
                self.parse_and_process_udp(phy, &ip_repr, packet, checksum_caps.udp.rx())
            }
            IpProtocol::Icmp if matches!(&ip_repr.inner, IpRepr::Ipv4(_)) => {
                self.process_icmp(phy, &ip_repr, packet, mtu)
            }
            _ => None,
        }
    }

    fn process_icmp(
        &mut self,
        phy: &dyn PollPhy,
        ip_repr: &IpReprWithLen,
        packet: RxPacket<TransportLayer>,
        mtu: usize,
    ) -> Option<TxPacketWithDst> {
        let mut bytes = alloc::vec![0; packet.len()];
        packet.reader().read(&mut VmWriter::from(bytes.as_mut_slice()));
        if self.iface.context().is_unicast(ip_repr.inner.src_addr())
            && self.iface.context().is_unicast(ip_repr.inner.dst_addr())
            && icmp::make_echo_reply(&mut bytes)
        {
            let reply = match &ip_repr.inner {
                IpRepr::Ipv4(ip) => IpRepr::Ipv4(Ipv4Repr {
                    src_addr: ip.dst_addr, dst_addr: ip.src_addr, next_header: IpProtocol::Icmp,
                    payload_len: bytes.len(), hop_limit: 64,
                }),
                _ => return None,
            };
            let mut builder = FreshTxPacket::<TransportLayer>::alloc(bytes.len()).ok()?.to_builder();
            let written = builder.append_writer().write(&mut VmReader::from(bytes.as_slice()));
            if written != bytes.len() { return None; }
            builder.commit(written);
            let path = self.udp_registry.path_mtu(self.ifindex, reply.dst_addr(), mtu);
            let packet = ip::emit_with_tos(builder.build(), &reply, self.iface.context().checksum_caps().ipv4.tx() || phy.is_loopback(), ip_repr.tos, false);
            let mut queue = self.raw_ip_tx.lock();
            if queue.len() < 64 {
                queue.push_back(TxPacketWithDst { packet, dst_addr: reply.dst_addr(), next_hop: IpNextHop::Routed, fragment_mtu: Some(path.mtu), failure: None });
            }
            return None;
        }
        let error = icmp::parse_udp_error(&bytes, true)?;
        if error.source.addr != ip_repr.inner.dst_addr() || !self.iface.is_unicast_local(error.source.addr) {
            return None;
        }
        for socket in self.udp_sockets {
            if socket.can_receive_error(error.source, self.ifindex) && socket.matches_error_destination(error.destination) {
                if error.type_ == 3 && error.code == 4
                    && let Some((egress, route)) = socket.path_mtu_egress(error.source, error.destination)
                {
                    self.udp_registry.update_path_mtu_for_route(egress, error.destination.addr, route, error.info as usize);
                }
                socket.report_error(UdpError {
                    destination: error.destination,
                    payload: error.payload.to_vec(),
                    timestamp_ns: 0,
                    origin: UdpErrorOrigin::Icmp {
                        offender: ip_repr.inner.src_addr(),
                        type_: error.type_,
                        code: error.code,
                        info: error.info,
                        ttl: match &ip_repr.inner { IpRepr::Ipv4(header) => header.hop_limit, _ => 0 },
                        tos: ip_repr.tos,
                    },
                });
            }
        }
        None
    }

    fn parse_and_process_tcp(
        &mut self,
        phy: &dyn PollPhy,
        ip_repr: &IpRepr,
        packet: RxPacket<TransportLayer>,
        verify_checksum: bool,
    ) -> Option<TxPacketWithDst> {
        // TCP connections can only be established between unicast addresses. Ignore the packet if
        // this is not the case. See
        // <https://datatracker.ietf.org/doc/html/rfc9293#section-3.9.2.3>.
        if !self.iface.context().is_unicast(ip_repr.src_addr())
            || !self.iface.context().is_unicast(ip_repr.dst_addr())
        {
            return None;
        }

        // Parse the TCP header. Ignore the packet if the header is ill-formed.
        let (packet, tcp_repr) = tcp::parse(packet, ip_repr, verify_checksum)?;

        let (ip_repr, tcp_repr) =
            self.process_tcp_until_outgoing(ip_repr, &tcp_repr, packet.reader().into())?;
        self.emit_tcp(phy, &ip_repr, &tcp_repr)
    }

    fn process_tcp_until_outgoing(
        &mut self,
        ip_repr: &IpRepr,
        tcp_repr: &TcpRepr,
        payload: PacketSlice<'_>,
    ) -> Option<(IpRepr, TcpRepr<'static>)> {
        let (mut ip_repr, mut tcp_repr) = self.process_tcp(ip_repr, tcp_repr, payload)?;

        loop {
            if !self.iface.is_unicast_local(ip_repr.dst_addr()) {
                return Some((ip_repr, tcp_repr));
            }

            let payload = PacketSlice::from(tcp_repr.payload);
            let (new_ip_repr, new_tcp_repr) = self.process_tcp(&ip_repr, &tcp_repr, payload)?;
            ip_repr = new_ip_repr;
            tcp_repr = new_tcp_repr;
        }
    }

    fn process_tcp(
        &mut self,
        ip_repr: &IpRepr,
        tcp_repr: &TcpRepr,
        payload: PacketSlice<'_>,
    ) -> Option<(IpRepr, TcpRepr<'static>)> {
        // Process packets belonging to existing connections first.
        // Note that we must do this first because SYN packets may match existing TIME-WAIT
        // sockets. See comments in `TcpConnectionBg::process` for details.
        let connection_key = ConnectionKey::new(
            ip_repr.dst_addr(),
            tcp_repr.dst_port,
            ip_repr.src_addr(),
            tcp_repr.src_port,
        );
        let mut connection_in_table = self.sockets.lookup_connection(&connection_key);

        loop {
            // First try the connection in the socket table, as this is the most common. If it
            // fails, it might mean that the connection is dead, the next step is to try the new
            // connections instead.
            let (should_break, connection) = if let Some(conn) = connection_in_table.take() {
                (false, Some(conn))
            } else {
                // Find in reverse order because old connections must have been dead.
                (
                    true,
                    self.actions
                        .iter()
                        .rev()
                        .flat_map(|action| match action {
                            SocketTableAction::AddTcpConn(conn) => Some(conn),
                            SocketTableAction::DelTcpConn(_) => None,
                        })
                        .find(|conn| conn.connection_key() == &connection_key),
                )
            };

            if let Some(connection) = connection {
                let (process_result, became_dead) =
                    connection.process(&mut self.iface, ip_repr, tcp_repr, payload.clone());
                if *became_dead {
                    self.actions
                        .push(SocketTableAction::DelTcpConn(*connection.connection_key()));
                }
                match process_result {
                    TcpProcessResult::NotProcessed => {}
                    TcpProcessResult::Processed => return None,
                    TcpProcessResult::ProcessedWithReply(ip_repr, tcp_repr) => {
                        return Some((ip_repr, tcp_repr));
                    }
                }
            }

            if should_break {
                break;
            }
        }

        // Process packets that request to create new connections second.
        if tcp_repr.control == TcpControl::Syn && tcp_repr.ack_number.is_none() {
            let listener_key = ListenerKey::new(ip_repr.dst_addr(), tcp_repr.dst_port);
            if let Some(listener) = self.sockets.lookup_listener(&listener_key) {
                let (processed, new_tcp_conn) =
                    listener.process(&mut self.iface, ip_repr, tcp_repr, payload.clone());

                if let Some(tcp_conn) = new_tcp_conn {
                    self.actions.push(SocketTableAction::AddTcpConn(tcp_conn));
                }

                match processed {
                    TcpProcessResult::NotProcessed => {}
                    TcpProcessResult::Processed => return None,
                    TcpProcessResult::ProcessedWithReply(ip_repr, tcp_repr) => {
                        return Some((ip_repr, tcp_repr));
                    }
                }
            }
        }

        // "In no case does receipt of a segment containing RST give rise to a RST in response."
        // See <https://datatracker.ietf.org/doc/html/rfc9293#section-4-1.64>.
        if tcp_repr.control == TcpControl::Rst {
            return None;
        }

        let (ip_repr, mut reply_repr) = smoltcp::socket::tcp::Socket::rst_reply(ip_repr, tcp_repr);
        if reply_repr.ack_number.is_some() {
            // Fix the ACK number, as the payload is kept outside of `TcpRepr`.
            reply_repr.ack_number =
                Some(tcp_repr.seq_number + tcp_repr.control.len() + payload.len());
        }
        Some((ip_repr, reply_repr))
    }

    fn parse_and_process_udp(
        &mut self,
        phy: &dyn PollPhy,
        ip_repr: &IpReprWithLen,
        packet: RxPacket<TransportLayer>,
        verify_checksum: bool,
    ) -> Option<TxPacketWithDst> {
        // Parse the UDP header. Ignore the packet if the header is ill-formed.
        let (packet, udp_repr) = udp::parse(packet, &ip_repr.inner, verify_checksum)?;

        if !self.process_udp(&ip_repr.inner, &udp_repr, packet.reader().into(), ip_repr.tos) {
            return self.generate_icmp_unreachable(
                phy,
                &ip_repr.inner,
                packet.reader_with_header(ip_repr.header_len + UDP_HEADER_LEN),
                Icmpv4DstUnreachable::PortUnreachable,
                ip_repr.tos,
            );
        }

        None
    }

    fn process_udp(
        &mut self,
        ip_repr: &IpRepr,
        udp_repr: &UdpRepr,
        udp_payload: PacketSlice<'_>,
        tos: u8,
    ) -> bool {
        let mut processed = false;
        let is_unicast = self.iface.context().is_unicast(ip_repr.dst_addr());

        for priority in (0..=7).rev() {
            if is_unicast {
                let candidates = || self.udp_sockets.iter().rev().filter(|socket|
                    socket.receive_priority(ip_repr, udp_repr, self.ifindex) == Some(priority));
                if let Some(first) = candidates().next() {
                    let group = || candidates().filter(|socket| first.same_reuse_port_group(socket));
                    let count = group().count();
                    let selected = if count > 1 {
                        let hash = hash_local_remote(ip_repr.dst_addr(), udp_repr.dst_port,
                            ip_repr.src_addr(), udp_repr.src_port);
                        group().nth(hash as usize % count).unwrap_or(first)
                    } else {
                        first
                    };
                    if selected.process(ip_repr, udp_repr, udp_payload.clone(), tos, self.ifindex) {
                        return true;
                    }
                }
            }
            for socket in self.udp_sockets.iter().rev() {
                if socket.receive_priority(ip_repr, udp_repr, self.ifindex) != Some(priority) {
                    continue;
                }
                processed |= socket.process(ip_repr, udp_repr, udp_payload.clone(), tos, self.ifindex);
                if processed && is_unicast {
                    return true;
                }
            }
        }

        processed
    }

    fn generate_icmp_unreachable(
        &mut self,
        phy: &dyn PollPhy,
        ip_repr: &IpRepr,
        mut ip_buffer: VmReader<'_, Infallible>,
        reason: Icmpv4DstUnreachable,
        original_tos: u8,
    ) -> Option<TxPacketWithDst> {
        // "An ICMP error message MUST NOT be sent as the result of receiving [..] a datagram
        // destined to an IP broadcast or IP multicast address, or [..] a datagram whose source
        // address does not define a single host."
        // Reference: <https://datatracker.ietf.org/doc/html/rfc1122#page-39>.
        if !self.iface.context().is_unicast(ip_repr.src_addr())
            || !self.iface.context().is_unicast(ip_repr.dst_addr())
        {
            return None;
        }

        let IpRepr::Ipv4(ipv4_repr) = ip_repr else {
            // TODO: Generate an IPv6 ICMP unreachable message.
            return None;
        };

        // "[..] the ICMP datagram SHOULD contain as much of the original datagram as possible
        // without the length of the ICMP datagram exceeding 576 bytes". See
        // <https://datatracker.ietf.org/doc/html/rfc1812#section-4.3.2.3>.
        let quote_len = ip_buffer
            .remain()
            .min(IPV4_MIN_MTU - IPV4_HEADER_LEN - icmp::HEADER_LEN);
        ip_buffer.limit(quote_len);
        let mut builder = match phy.alloc_tx_buffer(quote_len) {
            Ok(buffer) => buffer.to_builder(),
            Err(err) => {
                ostd::error!("failed to allocate a network packet: {:?}", err);
                return None;
            }
        };
        let written_len = builder.append_writer().write(&mut ip_buffer);
        debug_assert_eq!(written_len, quote_len);
        builder.commit(written_len);

        let reply_ip_repr = IpRepr::Ipv4(Ipv4Repr {
            src_addr: self
                .iface
                .context()
                .ipv4_addr()
                .unwrap_or(Ipv4Address::UNSPECIFIED),
            dst_addr: ipv4_repr.src_addr,
            next_header: IpProtocol::Icmp,
            payload_len: icmp::HEADER_LEN + quote_len,
            hop_limit: 64,
        });
        let checksum_caps = self.iface.context().checksum_caps();
        let packet = icmp::emit_dst_unreachable(builder.build(), reason, checksum_caps.icmpv4.tx() || phy.is_loopback());
        let packet = ip::emit_with_tos(packet, &reply_ip_repr, checksum_caps.ipv4.tx() || phy.is_loopback(), icmp::reply_tos(original_tos), true);

        Some(TxPacketWithDst {
            packet,
            dst_addr: reply_ip_repr.dst_addr(),
            next_hop: IpNextHop::Routed,
            fragment_mtu: None,
            failure: None,
        })
    }

    fn emit_tcp(
        &self,
        phy: &dyn PollPhy,
        ip_repr: &IpRepr,
        tcp_repr: &TcpRepr<'_>,
    ) -> Option<TxPacketWithDst> {
        let checksum_caps = self.iface.context().checksum_caps();

        let packet = Self::copy_payload(phy, tcp_repr.payload)?;
        let packet = tcp::emit(packet, ip_repr, tcp_repr, checksum_caps.tcp.tx());
        let packet = ip::emit(packet, ip_repr, checksum_caps.ipv4.tx());

        Some(TxPacketWithDst {
            packet,
            dst_addr: ip_repr.dst_addr(),
            next_hop: IpNextHop::Routed,
            fragment_mtu: None,
            failure: None,
        })
    }

    fn emit_udp(
        &self,
        phy: &dyn PollPhy,
        ip_repr: &IpRepr,
        udp_repr: &UdpRepr,
        payload: &[u8],
        tos: u8,
        next_hop: IpNextHop,
        fragmentation: UdpFragmentation,
        ipv4_options: Option<&UdpIpv4Options>,
    ) -> Option<TxPacketWithDst> {
        let checksum_caps = self.iface.context().checksum_caps();

        let packet = Self::copy_payload(phy, payload)?;
        let mut checksum_ip = ip_repr.clone();
        if let (IpRepr::Ipv4(ip), Some(options)) = (&mut checksum_ip, ipv4_options)
            && let Some(first_hop) = options.first_hop()
        { ip.dst_addr = first_hop; }
        let packet = udp::emit(packet, &checksum_ip, udp_repr,
            checksum_caps.udp.tx() || ipv4_options.is_some() || matches!(fragmentation, UdpFragmentation::Allow(_)));
        let dont_fragment = matches!(fragmentation, UdpFragmentation::DontFragment);
        let mut dst_addr = ip_repr.dst_addr();
        let packet = match (ip_repr, ipv4_options) {
            (IpRepr::Ipv4(ip), Some(options)) => {
                let dst = options.first_hop().unwrap_or(ip.dst_addr);
                dst_addr = dst.into();
                ip::emit_v4_with_options(packet, ip, dst, tos, dont_fragment, options.bytes())
            }
            (_, None) => ip::emit_with_tos(packet, ip_repr, checksum_caps.ipv4.tx(), tos, dont_fragment),
            _ => return None,
        };
        if !self.iface.context().is_unicast(dst_addr) {
            // Force the link layer to emit a broadcast link-layer address.
            dst_addr = IpAddress::Ipv4(Ipv4Address::BROADCAST);
        }

        Some(TxPacketWithDst { packet, dst_addr, next_hop, fragment_mtu: match fragmentation { UdpFragmentation::Allow(mtu) => Some(mtu), UdpFragmentation::DontFragment => None }, failure: None })
    }

    fn copy_payload(phy: &dyn PollPhy, payload: &[u8]) -> Option<TxPacket<ApplicationLayer>> {
        let mut builder = match phy.alloc_tx_buffer(payload.len()) {
            Ok(buffer) => buffer.to_builder(),
            Err(err) => {
                ostd::error!("failed to allocate a network packet: {:?}", err);
                return None;
            }
        };

        let written_len = builder.append_writer().write(&mut VmReader::from(payload));
        debug_assert_eq!(written_len, payload.len());
        builder.commit(written_len);

        Some(builder.build())
    }
}

impl<E: Ext> PollContext<'_, E> {
    pub(super) fn poll_egress(
        &mut self,
        device: &mut dyn AnyNetworkDevice,
        phy: &dyn PollPhy,
        taps: &LinkTaps,
    ) {
        let ipv4_cidrs = self.iface.ipv4_cidrs();
        while device.can_send() {
            if let Some(frame) = phy.take_neighbor_frame(self.iface.context_mut(), ipv4_cidrs) {
                if let Err(err) = send_frame(device, phy, taps, frame) {
                    ostd::error!("failed to send a network packet: {:?}", err);
                    break;
                }
                continue;
            }

            let (did_something, packet) = match self.iface.pending_fragments().pop_front() {
                Some(packet) => (true, Some(packet)),
                None => self.dispatch_ip(phy),
            };

            let packet = if let Some(mut packet) = packet {
                let mtu = packet.fragment_mtu.unwrap_or(device.mtu()).min(device.mtu());
                if packet.packet.len() > mtu {
                    let csum = self.iface.context().checksum_caps().ipv4.tx();
                    if let Some(fragments) = ip::fragment(&packet.packet, mtu, csum, |len| phy.alloc_tx_buffer(len)) {
                        let pending = self.iface.pending_fragments();
                        for (index, fragment) in fragments.into_iter().enumerate() {
                            pending.push_back(TxPacketWithDst {
                                packet: fragment,
                                dst_addr: packet.dst_addr,
                                next_hop: packet.next_hop,
                                fragment_mtu: None,
                                failure: if index == 0 { packet.failure.take() } else { None },
                            });
                        }
                    }
                    continue;
                }
                Some(packet)
            } else {
                None
            };

            if let Some(packet) = packet
                && let Some(tx_packet) = phy.dispatch(packet, self.iface.context_mut(), ipv4_cidrs)
                && let Err(err) = send_frame(device, phy, taps, tx_packet)
            {
                ostd::error!("failed to send a network packet: {:?}", err);
                break;
            }

            if phy.is_loopback() {
                self.poll_ingress(device, phy, taps);
            }

            if !did_something {
                break;
            }
        }
    }

    fn dispatch_ip(&mut self, phy: &dyn PollPhy) -> (bool, Option<TxPacketWithDst>) {
        if let Some(packet) = self.raw_ip_tx.lock().pop_front() {
            return (true, Some(packet));
        }
        let (did_something_tcp, tx_packet) = self.dispatch_tcp(phy);

        if tx_packet.is_some() {
            return (did_something_tcp, tx_packet);
        }

        let (did_something_udp, tx_packet) = self.dispatch_udp(phy);

        (did_something_tcp || did_something_udp, tx_packet)
    }

    fn dispatch_tcp(&mut self, phy: &dyn PollPhy) -> (bool, Option<TxPacketWithDst>) {
        let mut tx_packet = None;
        let mut did_something = false;

        loop {
            let Some(socket) = self.iface.pop_pending_tcp() else {
                break;
            };

            // We set `did_something` even if no packets are actually generated. This is because a
            // timer can expire, but no packets are actually generated.
            did_something = true;

            let mut deferred = None;

            let (reply, became_dead) =
                TcpConnectionBg::dispatch(&socket, &mut self.iface, |iface, ip_repr, tcp_repr| {
                    let mut this = PollContext::new(iface, self.sockets, self.udp_sockets, self.udp_registry, self.ip_taps, self.raw_ip_tx, self.ifindex, self.actions);

                    if !this.iface.is_unicast_local(ip_repr.dst_addr()) {
                        tx_packet = this.emit_tcp(phy, ip_repr, tcp_repr);
                        return None;
                    }

                    if !socket.can_process(tcp_repr.dst_port) {
                        return this.process_tcp(
                            ip_repr,
                            tcp_repr,
                            PacketSlice::from(tcp_repr.payload),
                        );
                    }

                    // We cannot call `process_tcp` now because it may cause deadlocks. We will copy
                    // the payload and call `process_tcp` after releasing the socket lock.
                    let repr: TcpRepr<'static> = TcpRepr {
                        payload: &[],
                        ..*tcp_repr
                    };
                    deferred = Some((ip_repr.clone(), repr, tcp_repr.payload.to_vec()));

                    None
                });

            if *became_dead {
                self.actions
                    .push(SocketTableAction::DelTcpConn(*socket.connection_key()));
            }

            match (deferred, reply) {
                (None, None) => (),
                (Some((ip_repr, tcp_repr, payload)), None) => {
                    if let Some((ip_repr, tcp_repr)) = self.process_tcp_until_outgoing(
                        &ip_repr,
                        &tcp_repr,
                        PacketSlice::from(payload.as_slice()),
                    ) {
                        tx_packet = self.emit_tcp(phy, &ip_repr, &tcp_repr);
                    }
                }
                (None, Some((ip_repr, tcp_repr)))
                    if !self.iface.is_unicast_local(ip_repr.dst_addr()) =>
                {
                    tx_packet = self.emit_tcp(phy, &ip_repr, &tcp_repr);
                }
                (None, Some((ip_repr, tcp_repr))) => {
                    if let Some((new_ip_repr, new_tcp_repr)) = self.process_tcp_until_outgoing(
                        &ip_repr,
                        &tcp_repr,
                        PacketSlice::from(tcp_repr.payload),
                    ) {
                        tx_packet = self.emit_tcp(phy, &new_ip_repr, &new_tcp_repr);
                    }
                }
                (Some(_), Some(_)) => unreachable!(),
            }

            if tx_packet.is_some() {
                break;
            }
        }

        (did_something, tx_packet)
    }

    fn dispatch_udp(&mut self, phy: &dyn PollPhy) -> (bool, Option<TxPacketWithDst>) {
        let mut tx_packet = None;
        let mut did_something = false;

        let mut actions = Vec::new();

        for socket in self.udp_sockets {
            if !socket.need_dispatch(self.ifindex) {
                continue;
            }

            // We set `did_something` even if no packets are actually generated. This is because a
            // timer can expire, but no packets are actually generated.
            did_something = true;

            let mut deferred = None;

            let (cx, pending, fragments, reassembly, ipv4_cidrs) = self.iface.inner_mut();
            socket.dispatch(self.ifindex, cx, |cx, ip_repr, udp_repr, udp_payload, tos, next_hop, fragmentation, ipv4_options| {
                let iface = PollableIfaceMut::new(cx, pending, fragments, reassembly, ipv4_cidrs);
                let mut this = PollContext::new(iface, self.sockets, self.udp_sockets, self.udp_registry, self.ip_taps, self.raw_ip_tx, self.ifindex, &mut actions);

                if ipv4_options.is_some() {
                    tx_packet = this.emit_udp(phy, ip_repr, udp_repr, udp_payload, tos, next_hop, fragmentation, ipv4_options);
                    if let Some(packet) = tx_packet.as_mut() {
                        packet.failure = Some((socket.failure_reporter(), smoltcp::wire::IpEndpoint::new(packet.dst_addr, udp_repr.dst_port)));
                    }
                    return;
                }
                let is_broadcast = this.iface.context().is_broadcast(&ip_repr.dst_addr());
                if phy.is_loopback() && this.iface.is_unicast_local(ip_repr.dst_addr()) && !is_broadcast {
                    tx_packet = this.emit_udp(phy, ip_repr, udp_repr, udp_payload, tos, next_hop, fragmentation, None);
                    return;
                }
                if is_broadcast || !this.iface.is_unicast_local(ip_repr.dst_addr()) {
                    tx_packet = this.emit_udp(phy, ip_repr, udp_repr, udp_payload, tos, next_hop, fragmentation, None);
                    if !is_broadcast {
                        if let Some(packet) = tx_packet.as_mut() {
                            packet.failure = Some((
                                socket.failure_reporter(),
                                smoltcp::wire::IpEndpoint::new(ip_repr.dst_addr(), udp_repr.dst_port),
                            ));
                        }
                        return;
                    }
                }

                if !socket.can_process(udp_repr.dst_port) {
                    let processed = this.process_udp(ip_repr, udp_repr, PacketSlice::from(udp_payload), tos);
                    if !processed && !is_broadcast {
                        socket.report_error(UdpError {
                            destination: smoltcp::wire::IpEndpoint::new(ip_repr.dst_addr(), udp_repr.dst_port),
                            payload: udp_payload.to_vec(),
                            timestamp_ns: 0,
                            origin: UdpErrorOrigin::Icmp {
                                offender: ip_repr.dst_addr(),
                                type_: 3,
                                code: 3,
                                info: 0,
                                ttl: 64,
                                tos: icmp::reply_tos(tos),
                            },
                        });
                    }
                    return;
                }

                // We cannot call `process_udp` now because it may cause deadlocks. We will copy
                // the payload and call `process_udp` after releasing the socket lock.
                deferred = Some((ip_repr.clone(), *udp_repr, udp_payload.to_vec(), is_broadcast, tos));
            });

            if let Some((ip_repr, udp_repr, payload, is_broadcast, tos)) = deferred {
                if !self.process_udp(&ip_repr, &udp_repr, PacketSlice::from(payload.as_slice()), tos) && !is_broadcast {
                    socket.report_error(UdpError {
                        destination: smoltcp::wire::IpEndpoint::new(ip_repr.dst_addr(), udp_repr.dst_port),
                        payload,
                        timestamp_ns: 0,
                        origin: UdpErrorOrigin::Icmp {
                            offender: ip_repr.dst_addr(),
                            type_: 3,
                            code: 3,
                            info: 0,
                            ttl: 64,
                            tos: icmp::reply_tos(tos),
                        },
                    });
                }
            }

            if tx_packet.is_some() {
                break;
            }
        }

        // `actions` should be empty,
        // because we are dealing with UDP sockets,
        // and the `actions` contains only TCP actions.
        debug_assert!(actions.is_empty());

        (did_something, tx_packet)
    }
}
