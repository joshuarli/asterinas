// SPDX-License-Identifier: MPL-2.0

use alloc::{collections::BTreeMap, vec, vec::Vec};
use core::sync::atomic::{AtomicU16, Ordering};

use int_to_c_enum::TryFromInt;
use ostd::mm::{VmReader, VmWriter};
use ostd_pod::IntoBytes;
use smoltcp::wire::{IpRepr, Ipv4Repr, Ipv6Repr};

use crate::{
    iface::wire::utils::{Be16, Checksum},
    packet::{FreshTxPacket, NetworkLayer, RxPacket, TransportLayer, TxPacket},
};

static NEXT_FRAGMENT_ID: AtomicU16 = AtomicU16::new(0);

const REASSEMBLY_LIMIT: usize = 64;
const REASSEMBLY_TIMEOUT_MS: i64 = 30_000;
const IPV4_MAX_PAYLOAD: usize = u16::MAX as usize - size_of::<HeaderV4>();

type FragmentKey = ([u8; 4], [u8; 4], u16, u8);

pub(crate) struct Ipv4Reassembly {
    packets: BTreeMap<FragmentKey, IncompletePacket>,
}

struct IncompletePacket {
    created_at: i64,
    header: Option<Vec<u8>>,
    data: Vec<u8>,
    received: Vec<u8>,
    received_len: usize,
    max_end: usize,
    ecn: u8,
    total_len: Option<usize>,
}

impl Ipv4Reassembly {
    pub(in crate::iface) fn new() -> Self {
        Self { packets: BTreeMap::new() }
    }

    pub(in crate::iface) fn receive(
        &mut self,
        packet: RxPacket<NetworkLayer>,
        now: i64,
        verify_checksum: bool,
        accepts_destination: impl FnOnce(smoltcp::wire::Ipv4Address) -> bool,
    ) -> Option<RxPacket<NetworkLayer>> {
        let version = packet.reader().read_val::<VersionAndIhl>().ok()?.version()?;
        if version != Version::V4 { return Some(packet); }
        let header = packet.reader().read_val::<HeaderV4>().ok()?;
        let flags = header.flags_frag.flags();
        let offset = header.flags_frag.fragment_offset() * 8;
        let header_len = header.ver_ihl.header_len();
        let total_len = usize::from(u16::from(header.totlen));
        if header_len < size_of::<HeaderV4>() || total_len < header_len || total_len > packet.len() {
            return None;
        }
        validate_input_options(&packet, header_len)?;
        if offset == 0 && !flags.contains(Flags::MF) { return Some(packet); }
        if !accepts_destination(header.dst.into()) || flags.contains(Flags::DF) || flags.contains(Flags::R) {
            return None;
        }
        let fragment_len = total_len - header_len;
        let end = offset.checked_add(fragment_len)?;
        if fragment_len == 0 || end > IPV4_MAX_PAYLOAD || flags.contains(Flags::MF) && fragment_len % 8 != 0 {
            return None;
        }
        if verify_checksum {
            let mut reader = packet.reader();
            reader.limit(header_len);
            if Checksum::new().with_reader(reader).finish() != u16::MAX { return None; }
        }
        self.packets.retain(|_, packet| now.saturating_sub(packet.created_at) < REASSEMBLY_TIMEOUT_MS);
        let key = (header.src, header.dst, header.ident.into(), header.proto);
        if !self.packets.contains_key(&key) {
            if self.packets.len() >= REASSEMBLY_LIMIT {
                let oldest = self.packets.iter().min_by_key(|(_, packet)| packet.created_at).map(|(key, _)| *key)?;
                self.packets.remove(&oldest);
            }
            self.packets.insert(key, IncompletePacket {
                created_at: now,
                header: None,
                data: vec![0; IPV4_MAX_PAYLOAD],
                received: vec![0; IPV4_MAX_PAYLOAD.div_ceil(8)],
                received_len: 0,
                max_end: 0,
                ecn: 0,
                total_len: None,
            });
        }
        let incomplete = self.packets.get_mut(&key)?;
        if incomplete.total_len.is_some_and(|total| end > total)
            || flags.contains(Flags::MF) && incomplete.total_len.is_some_and(|total| end >= total)
            || !flags.contains(Flags::MF) && incomplete.total_len.is_some_and(|total| total != end)
            || !flags.contains(Flags::MF) && incomplete.max_end > end
        {
            self.packets.remove(&key);
            return None;
        }
        let mut bytes = vec![0; fragment_len];
        let mut reader = packet.reader();
        reader.skip(header_len);
        reader.read(&mut VmWriter::from(bytes.as_mut_slice()));
        let overlap = (offset..end).filter(|i| incomplete.received[i / 8] & (1 << (i % 8)) != 0).count();
        if overlap != 0 {
            if overlap != fragment_len || incomplete.data[offset..end] != bytes {
                self.packets.remove(&key);
            }
            return None;
        }
        incomplete.data[offset..end].copy_from_slice(&bytes);
        for i in offset..end { incomplete.received[i / 8] |= 1 << (i % 8); }
        incomplete.received_len += fragment_len;
        incomplete.max_end = incomplete.max_end.max(end);
        incomplete.ecn |= 1 << (header.dscp_ecn.0 & 3);
        if !flags.contains(Flags::MF) { incomplete.total_len = Some(end); }
        if offset == 0 {
            let mut bytes = vec![0; header_len];
            packet.reader().read(&mut VmWriter::from(bytes.as_mut_slice()));
            incomplete.header = Some(bytes);
        }
        let total = incomplete.total_len?;
        if incomplete.received_len != total || incomplete.header.is_none() { return None; }
        let mut incomplete = self.packets.remove(&key)?;
        let mut header = incomplete.header.take()?;
        if incomplete.ecn & 1 != 0 && incomplete.ecn & !1 != 0 { return None; }
        if incomplete.ecn & 8 != 0 && incomplete.ecn & 6 != 0 { header[1] |= 3; }
        let packet_len = header.len() + total;
        if packet_len > u16::MAX as usize { return None; }
        header[2..4].copy_from_slice(&(packet_len as u16).to_be_bytes());
        header[6..8].fill(0);
        header[10..12].fill(0);
        let csum = !Checksum::new().with_bytes(&header).finish();
        header[10..12].copy_from_slice(&csum.to_ne_bytes());
        let mut builder = FreshTxPacket::<NetworkLayer>::alloc(header.len() + total).ok()?.to_builder();
        let header_written = builder.append_writer().write(&mut VmReader::from(header.as_slice()));
        builder.commit(header_written);
        let data_written = builder.append_writer().write(&mut VmReader::from(&incomplete.data[..total]));
        builder.commit(data_written);
        if header_written != header.len() || data_written != total { return None; }
        builder.build().to_rx_packet()
    }
}

fn validate_input_options(packet: &RxPacket<NetworkLayer>, header_len: usize) -> Option<()> {
    if header_len == size_of::<HeaderV4>() { return Some(()); }
    let mut options = vec![0; header_len - size_of::<HeaderV4>()];
    let mut reader = packet.reader();
    reader.skip(size_of::<HeaderV4>());
    reader.read(&mut VmWriter::from(options.as_mut_slice()));
    let mut offset = 0;
    while offset < options.len() {
        match options[offset] {
            0 => break,
            1 => offset += 1,
            131 | 137 => return None,
            _ => {
                let len = usize::from(*options.get(offset + 1)?);
                if len < 2 || offset + len > options.len() { return None; }
                offset += len;
            }
        }
    }
    Some(())
}

pub(in crate::iface) fn fragment<F>(
    pkt: &TxPacket<NetworkLayer>,
    mtu: usize,
    csum: bool,
    mut allocate: F,
) -> Option<Vec<TxPacket<NetworkLayer>>>
where
    F: FnMut(usize) -> Result<FreshTxPacket, ostd::Error>,
{
    let mut reader = pkt.reader();
    let header = reader.read_val::<HeaderV4>().ok()?;
    let header_len = header.ver_ihl.header_len();
    if header.ver_ihl.version() != Some(Version::V4)
        || header_len < size_of::<HeaderV4>() || header_len > 60 || header_len > pkt.len()
        || header.flags_frag.flags().intersects(Flags::DF | Flags::MF)
        || header.flags_frag.fragment_offset() != 0
        || usize::from(u16::from(header.totlen)) != pkt.len()
    {
        return None;
    }
    let fragment_len = mtu.checked_sub(header_len)? & !7;
    if fragment_len == 0 { return None; }
    let mut options = vec![0; header_len - size_of::<HeaderV4>()];
    reader.read(&mut VmWriter::from(options.as_mut_slice()));
    let mut payload = vec![0; pkt.len() - header_len];
    reader.read(&mut VmWriter::from(payload.as_mut_slice()));
    let mut fragments = Vec::new();
    for (index, chunk) in payload.chunks(fragment_len).enumerate() {
        let offset = index * fragment_len;
        let mut builder = allocate(chunk.len()).ok()?.to_builder_at_layer::<TransportLayer>();
        let written = builder.append_writer().write(&mut VmReader::from(chunk));
        if written != chunk.len() { return None; }
        builder.commit(written);
        let mut fragment_header = header;
        fragment_header.totlen = ((header_len + chunk.len()) as u16).into();
        let flags = if offset + chunk.len() < payload.len() { Flags::MF } else { Flags::empty() };
        fragment_header.flags_frag = FlagsAndFragmentOffset::new(flags, offset / 8);
        fragment_header.csum = 0;
        if csum {
            fragment_header.csum = !Checksum::new().with_bytes(fragment_header.as_bytes()).with_bytes(&options).finish();
        }
        let mut fragment = builder.build();
        let mut writer = fragment.prepend_writer(header_len);
        writer.write_val(&fragment_header).ok()?;
        if writer.write(&mut VmReader::from(options.as_slice())) != options.len() { return None; }
        drop(writer);
        fragments.push(fragment.pack(header_len));
    }
    Some(fragments)
}

pub(in crate::iface) fn parse(
    pkt: RxPacket<NetworkLayer>,
    ver: Option<Version>,
    csum: bool,
) -> Option<(RxPacket<TransportLayer>, IpReprWithLen)> {
    let pkt_ver = {
        let byte0 = pkt.reader().read_val::<VersionAndIhl>().ok()?;
        byte0.version()?
    };

    if ver.is_some_and(|v| v != pkt_ver) {
        return None;
    }

    match pkt_ver {
        Version::V4 => do_parse_v4(pkt, csum),
        Version::V6 => do_parse_v6(pkt),
    }
}

fn do_parse_v4(
    mut pkt: RxPacket<NetworkLayer>,
    csum: bool,
) -> Option<(RxPacket<TransportLayer>, IpReprWithLen)> {
    let header = pkt.reader().read_val::<HeaderV4>().ok()?;
    debug_assert_eq!(header.ver_ihl.version(), Some(Version::V4));

    let header_len = header.ver_ihl.header_len();
    let total_len = u16::from(header.totlen) as usize;
    if header_len < size_of::<HeaderV4>() || total_len < header_len || total_len > pkt.len() {
        return None;
    }
    pkt.truncate(total_len);

    if header.flags_frag.flags().contains(Flags::MF) || header.flags_frag.fragment_offset() != 0 {
        return None;
    }

    if csum {
        let mut reader = pkt.reader();
        reader.limit(header_len);
        if Checksum::new().with_reader(reader).finish() != u16::MAX {
            return None;
        }
    }

    validate_input_options(&pkt, header_len)?;

    let inner = Ipv4Repr {
        src_addr: header.src.into(),
        dst_addr: header.dst.into(),
        next_header: header.proto.into(),
        payload_len: total_len - header_len,
        hop_limit: header.ttl,
    };
    let repr = IpReprWithLen {
        inner: IpRepr::Ipv4(inner),
        header_len,
        tos: header.dscp_ecn.0,
    };
    Some((pkt.peel(header_len), repr))
}

fn do_parse_v6(
    mut pkt: RxPacket<NetworkLayer>,
) -> Option<(RxPacket<TransportLayer>, IpReprWithLen)> {
    let header = pkt.reader().read_val::<HeaderV6>().ok()?;
    debug_assert_eq!(header.ver_flow.version(), Some(Version::V6));

    let payload_len = u16::from(header.len) as usize;
    let total_len = size_of::<HeaderV6>() + payload_len;
    if total_len > pkt.len() {
        return None;
    }
    pkt.truncate(total_len);

    let inner = Ipv6Repr {
        src_addr: header.src.into(),
        dst_addr: header.dst.into(),
        next_header: header.next.into(),
        payload_len,
        hop_limit: header.hops,
    };
    let repr = IpReprWithLen {
        inner: IpRepr::Ipv6(inner),
        header_len: size_of::<HeaderV6>(),
        tos: 0,
    };
    Some((pkt.peel(size_of::<HeaderV6>()), repr))
}

pub(in crate::iface) fn emit(
    pkt: TxPacket<TransportLayer>,
    ip_repr: &IpRepr,
    csum: bool,
) -> TxPacket<NetworkLayer> {
    emit_with_tos(pkt, ip_repr, csum, 0, true)
}

pub(in crate::iface) fn emit_with_tos(
    pkt: TxPacket<TransportLayer>,
    ip_repr: &IpRepr,
    csum: bool,
    tos: u8,
    dont_fragment: bool,
) -> TxPacket<NetworkLayer> {
    match ip_repr {
        IpRepr::Ipv4(ipv4_repr) => emit_v4(pkt, ipv4_repr, csum, tos, dont_fragment),
        IpRepr::Ipv6(ipv6_repr) => emit_v6(pkt, ipv6_repr),
    }
}

pub(in crate::iface) fn emit_v4_with_options(
    mut pkt: TxPacket<TransportLayer>,
    ipv4_repr: &Ipv4Repr,
    dst: smoltcp::wire::Ipv4Address,
    tos: u8,
    dont_fragment: bool,
    options: &[u8],
) -> TxPacket<NetworkLayer> {
    let header_len = size_of::<HeaderV4>() + options.len();
    let mut header = HeaderV4 {
        ver_ihl: VersionAndIhl::new(Version::V4, header_len),
        dscp_ecn: DscpAndEcn(tos),
        totlen: ((ipv4_repr.payload_len + header_len) as u16).into(),
        ident: if dont_fragment { 0 } else { NEXT_FRAGMENT_ID.fetch_add(1, Ordering::Relaxed) }.into(),
        flags_frag: FlagsAndFragmentOffset::new(if dont_fragment { Flags::DF } else { Flags::empty() }, 0),
        ttl: ipv4_repr.hop_limit,
        proto: ipv4_repr.next_header.into(),
        csum: 0,
        src: ipv4_repr.src_addr.octets(),
        dst: dst.octets(),
    };
    header.csum = !Checksum::new().with_bytes(header.as_bytes()).with_bytes(options).finish();
    let mut writer = pkt.prepend_writer(header_len);
    writer.write_val(&header).unwrap();
    writer.write(&mut VmReader::from(options));
    drop(writer);
    pkt.pack(header_len)
}

fn emit_v4(
    pkt: TxPacket<TransportLayer>,
    ipv4_repr: &Ipv4Repr,
    csum: bool,
    tos: u8,
    dont_fragment: bool,
) -> TxPacket<NetworkLayer> {
    debug_assert_eq!(ipv4_repr.payload_len, pkt.len());

    let mut header = HeaderV4 {
        ver_ihl: VersionAndIhl::new(Version::V4, size_of::<HeaderV4>()),
        dscp_ecn: DscpAndEcn(tos),
        totlen: ((ipv4_repr.payload_len + size_of::<HeaderV4>()) as u16).into(),
        ident: if dont_fragment { 0 } else { NEXT_FRAGMENT_ID.fetch_add(1, Ordering::Relaxed) }.into(),
        flags_frag: FlagsAndFragmentOffset::new(if dont_fragment { Flags::DF } else { Flags::empty() }, 0),
        ttl: ipv4_repr.hop_limit,
        proto: ipv4_repr.next_header.into(),
        csum: 0,
        src: ipv4_repr.src_addr.octets(),
        dst: ipv4_repr.dst_addr.octets(),
    };

    if csum {
        header.csum = !Checksum::new().with_bytes(header.as_bytes()).finish();
    }

    pkt.prepend_and_pack(&header)
}

fn emit_v6(pkt: TxPacket<TransportLayer>, ipv6_repr: &Ipv6Repr) -> TxPacket<NetworkLayer> {
    debug_assert_eq!(ipv6_repr.payload_len, pkt.len());

    let header = HeaderV6 {
        // If necessary, we should fill the flow label field.
        ver_flow: VersionToFlowLabel::new(Version::V6, Dscp::Cs0, Ecn::NotEct, 0),
        len: (ipv6_repr.payload_len as u16).into(),
        next: ipv6_repr.next_header.into(),
        hops: ipv6_repr.hop_limit,
        src: ipv6_repr.src_addr.octets(),
        dst: ipv6_repr.dst_addr.octets(),
    };

    pkt.prepend_and_pack(&header)
}

#[derive(Clone, Debug)]
pub(in crate::iface) struct IpReprWithLen {
    pub inner: IpRepr,
    pub header_len: usize,
    pub tos: u8,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Pod)]
struct HeaderV4 {
    ver_ihl: VersionAndIhl,
    dscp_ecn: DscpAndEcn,
    totlen: Be16,
    ident: Be16,
    flags_frag: FlagsAndFragmentOffset,
    ttl: u8,
    proto: u8,
    csum: u16,
    src: [u8; 4],
    dst: [u8; 4],
}

#[repr(transparent)]
#[derive(Clone, Copy, Debug, Pod)]
struct VersionAndIhl(u8);

#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, TryFromInt)]
pub(in crate::iface) enum Version {
    V4 = 4,
    V6 = 6,
}

impl VersionAndIhl {
    fn new(version: Version, header_len: usize) -> Self {
        Self(((version as u8) << 4) | (header_len as u8 / 4))
    }

    fn version(self) -> Option<Version> {
        Version::try_from(self.0 >> 4).ok()
    }

    fn header_len(self) -> usize {
        (self.0 as usize & 0xf) * 4
    }
}

#[repr(transparent)]
#[derive(Clone, Copy, Debug, Pod)]
struct DscpAndEcn(u8);

#[repr(u8)]
#[derive(Clone, Copy, Debug)]
enum Dscp {
    Cs0 = 0,
    // Add other variants (e.g., `Cs1`) when needed.
}

#[repr(u8)]
#[derive(Clone, Copy, Debug)]
enum Ecn {
    NotEct = 0b00,
    // Add other variants (e.g., `Ect1`) when needed.
}

#[repr(transparent)]
#[derive(Clone, Copy, Debug, Pod)]
struct FlagsAndFragmentOffset([u8; 2]);

bitflags::bitflags! {
    struct Flags: u8 {
        const R  = 1 << 2;
        const DF = 1 << 1;
        const MF = 1 << 0;
    }
}

impl FlagsAndFragmentOffset {
    fn new(flags: Flags, fragment_offset: usize) -> Self {
        debug_assert_eq!(fragment_offset >> 13, 0);
        Self([
            (flags.bits() << 5) | ((fragment_offset >> 8) as u8),
            fragment_offset as u8,
        ])
    }

    fn flags(self) -> Flags {
        Flags::from_bits_truncate(self.0[0] >> 5)
    }

    fn fragment_offset(self) -> usize {
        self.0[1] as usize | ((self.0[0] as usize & 0x1f) << 8)
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Pod)]
struct HeaderV6 {
    ver_flow: VersionToFlowLabel,
    len: Be16,
    next: u8,
    hops: u8,
    src: [u8; 16],
    dst: [u8; 16],
}

#[repr(transparent)]
#[derive(Clone, Copy, Debug, Pod)]
struct VersionToFlowLabel([u8; 4]);

impl VersionToFlowLabel {
    fn new(version: Version, dscp: Dscp, ecn: Ecn, flow_label: u32) -> Self {
        debug_assert_eq!(flow_label >> 20, 0);
        Self([
            ((version as u8) << 4) | (dscp as u8 >> 2),
            ((dscp as u8) << 6) | ((ecn as u8) << 4) | ((flow_label >> 16) as u8),
            (flow_label >> 8) as u8,
            flow_label as u8,
        ])
    }

    fn version(self) -> Option<Version> {
        Version::try_from(self.0[0] >> 4).ok()
    }
}

#[cfg(ktest)]
mod test {
    use ostd::prelude::ktest;
    use smoltcp::wire::{IpProtocol, Ipv4Address};

    use super::*;

    fn fragmentable_packet() -> TxPacket<NetworkLayer> {
        let payload = [0x5a; 32];
        let mut builder = FreshTxPacket::<TransportLayer>::alloc(payload.len()).unwrap().to_builder();
        let written = builder.append_writer().write(&mut VmReader::from(payload.as_slice()));
        builder.commit(written);
        emit_v4(builder.build(), &Ipv4Repr {
            src_addr: Ipv4Address::new(192, 0, 2, 1),
            dst_addr: Ipv4Address::new(192, 0, 2, 2),
            next_header: IpProtocol::Udp,
            payload_len: payload.len(),
            hop_limit: 64,
        }, true, 0, false)
    }

    #[ktest]
    fn fragmentable_datagrams_have_distinct_identifiers() {
        let first = fragmentable_packet().reader().read_val::<HeaderV4>().unwrap();
        let second = fragmentable_packet().reader().read_val::<HeaderV4>().unwrap();
        assert_ne!(u16::from(first.ident), u16::from(second.ident));
        assert!(!first.flags_frag.flags().contains(Flags::DF));
        assert!(!second.flags_frag.flags().contains(Flags::DF));
    }

    #[ktest]
    fn fragments_preserve_the_original_datagram_identifier() {
        let original = fragmentable_packet();
        let identifier = u16::from(original.reader().read_val::<HeaderV4>().unwrap().ident);
        let fragments = fragment(&original, 36, true, FreshTxPacket::alloc).unwrap();
        assert_eq!(fragments.len(), 2);
        for packet in fragments {
            let header = packet.reader().read_val::<HeaderV4>().unwrap();
            assert_eq!(u16::from(header.ident), identifier);
        }
    }

    #[ktest]
    fn source_route_on_a_later_fragment_is_rejected_before_reassembly() {
        let original = fragmentable_packet();
        let mut fragments = fragment(&original, 36, true, FreshTxPacket::alloc).unwrap().into_iter();
        let first = fragments.next().unwrap().to_rx_packet().unwrap();
        let last = fragments.next().unwrap();
        let mut reader = last.reader();
        let mut header = reader.read_val::<HeaderV4>().unwrap();
        let mut payload = [0u8; 16];
        reader.read(&mut VmWriter::from(payload.as_mut_slice()));
        let options = [1, 131, 7, 4, 192, 0, 2, 9];
        header.ver_ihl = VersionAndIhl::new(Version::V4, 28);
        header.totlen = 44u16.into();
        header.csum = 0;
        header.csum = !Checksum::new().with_bytes(header.as_bytes()).with_bytes(&options).finish();
        let mut builder = FreshTxPacket::<NetworkLayer>::alloc(44).unwrap().to_builder();
        for bytes in [header.as_bytes(), options.as_slice(), payload.as_slice()] {
            let written = builder.append_writer().write(&mut VmReader::from(bytes));
            builder.commit(written);
        }
        let disallowed = builder.build().to_rx_packet().unwrap();
        let mut reassembly = Ipv4Reassembly::new();
        assert!(reassembly.receive(first, 0, true, |_| true).is_none());
        assert!(reassembly.receive(disallowed, 0, true, |_| true).is_none());
        assert!(reassembly.receive(last.to_rx_packet().unwrap(), 0, true, |_| true).is_some());
    }

    #[ktest]
    fn fragments_for_ineligible_destinations_allocate_no_reassembly_state() {
        let original = fragmentable_packet();
        let fragments = fragment(&original, 36, true, FreshTxPacket::alloc).unwrap();
        let mut reassembly = Ipv4Reassembly::new();
        for fragment in fragments {
            let packet = fragment.to_rx_packet().unwrap();
            assert!(reassembly.receive(packet, 0, true, |_| false).is_none());
            assert!(reassembly.packets.is_empty());
        }
    }
}
