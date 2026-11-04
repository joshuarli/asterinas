// SPDX-License-Identifier: MPL-2.0

use alloc::{vec, vec::Vec};
use int_to_c_enum::TryFromInt;
use ostd::mm::{Infallible, VmReader, VmWriter};
use ostd_pod::IntoBytes;
use smoltcp::wire::{IpProtocol, IpRepr, TcpControl, TcpRepr, TcpSeqNumber, TcpTimestampRepr};

use crate::{
    iface::wire::utils::{Be16, Be32, Checksum},
    packet::{ApplicationLayer, FreshTxPacket, NetworkLayer, RxPacket, TransportLayer, TxPacket},
};

pub(in crate::iface) fn outgoing_sequence_range(packet: &TxPacket<NetworkLayer>) -> Option<(u32, u32)> {
    let mut bytes = vec![0; packet.len()];
    packet.reader().read(&mut VmWriter::from(bytes.as_mut_slice()));
    let ip_len = usize::from(*bytes.first()? & 15) * 4;
    if bytes.len() < ip_len + 20 || bytes[0] >> 4 != 4 || bytes[9] != 6 { return None; }
    let tcp_len = usize::from(bytes[ip_len + 12] >> 4) * 4;
    if tcp_len < 20 || bytes.len() < ip_len + tcp_len { return None; }
    let sequence = u32::from_be_bytes(bytes[ip_len + 4..ip_len + 8].try_into().ok()?);
    let flags = bytes[ip_len + 13];
    let length = bytes.len() - ip_len - tcp_len + usize::from(flags & 0x02 != 0) + usize::from(flags & 0x01 != 0);
    (length != 0).then_some((sequence, sequence.wrapping_add(length as u32)))
}

pub(in crate::iface) fn segment<F>(packet: &TxPacket<NetworkLayer>, mtu: usize, mut allocate: F) -> Option<Vec<TxPacket<NetworkLayer>>>
where F: FnMut(usize) -> Result<FreshTxPacket, ostd::Error> {
    let mut bytes = vec![0; packet.len()];
    packet.reader().read(&mut VmWriter::from(bytes.as_mut_slice()));
    let ip_len = usize::from(*bytes.first()? & 15) * 4;
    if bytes.len() < ip_len + 20 || bytes[0] >> 4 != 4 || bytes[9] != 6 { return None; }
    let tcp_len = usize::from(bytes[ip_len + 12] >> 4) * 4;
    if tcp_len < 20 || bytes.len() < ip_len + tcp_len || bytes[ip_len + 13] & 0x06 != 0 { return None; }
    let data_offset = ip_len + tcp_len;
    let chunk_len = mtu.checked_sub(data_offset)?;
    if chunk_len == 0 { return None; }
    let payload = &bytes[data_offset..];
    if payload.is_empty() { return None; }
    let sequence = u32::from_be_bytes(bytes[ip_len + 4..ip_len + 8].try_into().ok()?);
    let mut packets = Vec::new();
    for (index, chunk) in payload.chunks(chunk_len).enumerate() {
        let offset = index * chunk_len;
        let mut part = bytes[..data_offset].to_vec();
        part.extend_from_slice(chunk);
        let total_len = part.len() as u16;
        part[2..4].copy_from_slice(&total_len.to_be_bytes());
        part[10..12].fill(0);
        let ip_checksum = !Checksum::new().with_bytes(&part[..ip_len]).finish();
        part[10..12].copy_from_slice(&ip_checksum.to_ne_bytes());
        part[ip_len + 4..ip_len + 8].copy_from_slice(&sequence.wrapping_add(offset as u32).to_be_bytes());
        if offset + chunk.len() != payload.len() { part[ip_len + 13] &= !(0x01 | 0x08); }
        part[ip_len + 16..ip_len + 18].fill(0);
        let mut pseudo = [0u8; 12];
        pseudo[..8].copy_from_slice(&part[12..20]);
        pseudo[9] = 6;
        pseudo[10..12].copy_from_slice(&((part.len() - ip_len) as u16).to_be_bytes());
        let tcp_checksum = !Checksum::new().with_bytes(&pseudo).with_bytes(&part[ip_len..]).finish();
        part[ip_len + 16..ip_len + 18].copy_from_slice(&tcp_checksum.to_ne_bytes());
        let mut builder = allocate(part.len()).ok()?.to_builder_at_layer::<NetworkLayer>();
        let written = builder.append_writer().write(&mut VmReader::from(part.as_slice()));
        if written != part.len() { return None; }
        builder.commit(written);
        packets.push(builder.build());
    }
    Some(packets)
}

pub(in crate::iface) fn parse(
    pkt: RxPacket<TransportLayer>,
    ip_repr: &IpRepr,
    csum: bool,
) -> Option<(RxPacket<ApplicationLayer>, TcpRepr<'static>)> {
    let header = pkt.reader().read_val::<Header>().ok()?;

    let header_len = header.header_len();
    if header_len < size_of::<Header>() || header_len > pkt.len() {
        return None;
    }

    let src_port = u16::from(header.src);
    let dst_port = u16::from(header.dst);
    if src_port == 0 || dst_port == 0 {
        // In practice, zero port numbers are not valid because none of the operating systems in
        // production can bind to them. They are reserved by the IANA:
        // <https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml>.
        return None;
    }

    let flags = Flags::from_bits_truncate(header.flags);
    let control = match (
        flags.contains(Flags::SYN),
        flags.contains(Flags::FIN),
        flags.contains(Flags::RST),
        flags.contains(Flags::PSH),
    ) {
        (false, false, false, false) => TcpControl::None,
        (false, false, false, true) => TcpControl::Psh,
        (true, false, false, _) => TcpControl::Syn,
        (false, true, false, _) => TcpControl::Fin,
        (false, false, true, _) => TcpControl::Rst,
        _ => return None,
    };

    let ack_number = flags
        .contains(Flags::ACK)
        .then(|| TcpSeqNumber(u32::from(header.ack) as i32));

    if csum
        && Checksum::new()
            .with_pseudo_header(ip_repr, pkt.len())
            .with_reader(pkt.reader())
            .finish()
            != u16::MAX
    {
        return None;
    }

    let mut repr = TcpRepr {
        src_port,
        dst_port,
        control,
        seq_number: TcpSeqNumber(u32::from(header.seq) as i32),
        ack_number,
        window_len: header.win.into(),
        window_scale: None,
        max_seg_size: None,
        sack_permitted: false,
        sack_ranges: [None; 3],
        timestamp: None,
        payload: &[],
    };

    if header_len != size_of::<Header>() {
        let mut options = pkt.reader();
        options
            .skip(size_of::<Header>())
            .limit(header_len - size_of::<Header>());
        if !parse_options(options, &mut repr) {
            return None;
        }
    }

    Some((pkt.peel(header_len), repr))
}

#[must_use]
fn parse_options(mut options: VmReader<Infallible>, repr: &mut TcpRepr<'static>) -> bool {
    while let Ok(kind) = options.read_val::<u8>() {
        let kind = OptionKind::try_from(kind).ok();
        match kind {
            Some(OptionKind::End) => break,
            Some(OptionKind::Nop) => continue,
            _ => {}
        }

        let Ok(option_len) = options.read_val::<u8>() else {
            return false;
        };
        let option_len = option_len as usize;
        if option_len < 2 || option_len - 2 > options.remain() {
            return false;
        }

        match (kind, option_len) {
            (Some(OptionKind::MaxSegmentSize), 4) => {
                repr.max_seg_size = Some(options.read_val::<Be16>().unwrap().into());
            }
            (Some(OptionKind::MaxSegmentSize), _) => return false,

            (Some(OptionKind::WindowScale), 3) => {
                // "Thus, the shift count MUST be limited to 14 (which allows windows of 2^30 = 1
                // GiB).  If a Window Scale option is received with a shift.cnt value larger than
                // 14, the TCP SHOULD log the error but MUST use 14 instead of the specified value."
                // Reference: <https://datatracker.ietf.org/doc/html/rfc7323#section-2.3>.
                repr.window_scale = Some(options.read_val::<u8>().unwrap().min(14));
            }
            (Some(OptionKind::WindowScale), _) => return false,

            (Some(OptionKind::SackPermitted), 2) => repr.sack_permitted = true,
            (Some(OptionKind::SackPermitted), _) => return false,

            (Some(OptionKind::SackRange), len) if len >= 10 && (len - 2) % 8 == 0 => {
                repr.sack_ranges = [None; 3];
                for index in 0..(len - 2) / 8 {
                    let left = options.read_val::<Be32>().unwrap().into();
                    let right = options.read_val::<Be32>().unwrap().into();
                    if let Some(range) = repr.sack_ranges.get_mut(index) {
                        *range = Some((left, right));
                    }
                }
            }
            (Some(OptionKind::SackRange), _) => return false,

            (Some(OptionKind::Timestamp), 10) => {
                let tsval = options.read_val::<Be32>().unwrap().into();
                let tsecr = options.read_val::<Be32>().unwrap().into();
                repr.timestamp = Some(TcpTimestampRepr::new(tsval, tsecr));
            }
            (Some(OptionKind::Timestamp), _) => return false,

            (Some(OptionKind::End | OptionKind::Nop), _) => unreachable!(),
            (None, len) => {
                options.skip(len - 2);
            }
        }
    }

    true
}

pub(in crate::iface) fn emit(
    mut pkt: TxPacket<ApplicationLayer>,
    ip_repr: &IpRepr,
    tcp_repr: &TcpRepr<'_>,
    csum: bool,
) -> TxPacket<TransportLayer> {
    debug_assert_eq!(ip_repr.next_header(), IpProtocol::Tcp);

    let header_len = tcp_repr.header_len();
    let packet_len = header_len + pkt.len();
    debug_assert_eq!(ip_repr.payload_len(), packet_len);

    let mut flags = match tcp_repr.control {
        TcpControl::None => Flags::empty(),
        TcpControl::Psh => Flags::PSH,
        TcpControl::Syn => Flags::SYN,
        TcpControl::Fin => Flags::FIN,
        TcpControl::Rst => Flags::RST,
    };
    if tcp_repr.ack_number.is_some() {
        flags.insert(Flags::ACK);
    }

    let mut header = Header {
        src: tcp_repr.src_port.into(),
        dst: tcp_repr.dst_port.into(),
        seq: (tcp_repr.seq_number.0 as u32).into(),
        ack: (tcp_repr.ack_number.unwrap_or(TcpSeqNumber(0)).0 as u32).into(),
        off: ((header_len / 4) as u8) << 4,
        flags: flags.bits(),
        win: tcp_repr.window_len.into(),
        csum: 0,
        urg: 0u16.into(),
    };

    let option_len = header_len - size_of::<Header>();
    if option_len != 0 {
        let writer = pkt.prepend_writer(option_len);
        emit_options(writer, tcp_repr);
    }

    if csum {
        let csum_val = !Checksum::new()
            .with_pseudo_header(ip_repr, packet_len)
            .with_bytes(header.as_bytes())
            .with_reader(pkt.reader_with_header(option_len))
            .finish();
        header.csum = csum_val;
    }

    pkt.prepend_writer(header_len).write_val(&header).unwrap();
    pkt.pack(header_len)
}

fn emit_options(mut writer: VmWriter<Infallible>, repr: &TcpRepr<'_>) {
    if let Some(value) = repr.max_seg_size {
        writer
            .write_val(&[OptionKind::MaxSegmentSize as u8, 4])
            .unwrap();
        writer.write_val(&Be16::from(value)).unwrap();
    }

    if let Some(value) = repr.window_scale {
        writer
            .write_val(&[OptionKind::WindowScale as u8, 3, value])
            .unwrap();
    }

    if repr.sack_permitted {
        writer
            .write_val(&[OptionKind::SackPermitted as u8, 2])
            .unwrap();
    }

    if repr.sack_ranges.iter().any(Option::is_some) {
        let range_count = repr.sack_ranges.iter().flatten().count();
        writer
            .write_val(&[OptionKind::SackRange as u8, (range_count * 8 + 2) as u8])
            .unwrap();
        for &(left, right) in repr.sack_ranges.iter().flatten() {
            writer.write_val(&Be32::from(left)).unwrap();
            writer.write_val(&Be32::from(right)).unwrap();
        }
    }

    if let Some(timestamp) = repr.timestamp {
        writer
            .write_val(&[OptionKind::Timestamp as u8, 10])
            .unwrap();
        writer.write_val(&Be32::from(timestamp.tsval)).unwrap();
        writer.write_val(&Be32::from(timestamp.tsecr)).unwrap();
    }

    let padding_len = writer.avail();
    writer.fill_zeros(padding_len);
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Pod)]
struct Header {
    src: Be16,
    dst: Be16,
    seq: Be32,
    ack: Be32,
    off: u8,
    flags: u8,
    win: Be16,
    csum: u16,
    urg: Be16,
}

impl Header {
    fn header_len(self) -> usize {
        (self.off as usize >> 4) * 4
    }
}

bitflags::bitflags! {
    struct Flags: u8 {
        const FIN = 1 << 0;
        const SYN = 1 << 1;
        const RST = 1 << 2;
        const PSH = 1 << 3;
        const ACK = 1 << 4;
        const URG = 1 << 5;
        const ECE = 1 << 6;
        const CWR = 1 << 7;
    }
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, TryFromInt)]
enum OptionKind {
    End = 0,
    Nop = 1,
    MaxSegmentSize = 2,
    WindowScale = 3,
    SackPermitted = 4,
    SackRange = 5,
    Timestamp = 8,
}

#[cfg(ktest)]
mod test {
    use ostd::prelude::ktest;
    use super::*;

    #[ktest]
    fn segments_preserve_tcp_stream_and_checksums() {
        let mut bytes = vec![0u8; 20 + 20 + 901];
        bytes[0] = 0x45;
        bytes[2..4].copy_from_slice(&(941u16).to_be_bytes());
        bytes[8] = 64;
        bytes[9] = 6;
        bytes[12..20].copy_from_slice(&[192, 0, 2, 1, 198, 51, 100, 9]);
        bytes[20..24].copy_from_slice(&[0x12, 0x34, 0x56, 0x78]);
        bytes[24..28].copy_from_slice(&0xffff_ff00u32.to_be_bytes());
        bytes[32] = 0x50;
        bytes[33] = 0x19;
        for (index, byte) in bytes[40..].iter_mut().enumerate() { *byte = index as u8; }
        let mut builder = FreshTxPacket::<ApplicationLayer>::alloc(bytes.len()).unwrap().to_builder_at_layer::<NetworkLayer>();
        let written = builder.append_writer().write(&mut VmReader::from(bytes.as_slice()));
        builder.commit(written);
        let packet = builder.build();
        let segments = segment(&packet, 600, FreshTxPacket::alloc).unwrap();
        assert_eq!(segments.len(), 2);
        let mut rebuilt = Vec::new();
        for (index, part) in segments.iter().enumerate() {
            let mut data = vec![0u8; part.len()];
            part.reader().read(&mut VmWriter::from(data.as_mut_slice()));
            assert!(data.len() <= 600);
            assert_eq!(Checksum::new().with_bytes(&data[..20]).finish(), u16::MAX);
            let mut pseudo = [0u8; 12];
            pseudo[..8].copy_from_slice(&data[12..20]);
            pseudo[9] = 6;
            pseudo[10..12].copy_from_slice(&((data.len() - 20) as u16).to_be_bytes());
            assert_eq!(Checksum::new().with_bytes(&pseudo).with_bytes(&data[20..]).finish(), u16::MAX);
            let seq = u32::from_be_bytes(data[24..28].try_into().unwrap());
            assert_eq!(seq, 0xffff_ff00u32.wrapping_add(rebuilt.len() as u32));
            assert_eq!(data[33] & 0x09, if index == 0 { 0 } else { 0x09 });
            rebuilt.extend_from_slice(&data[40..]);
        }
        assert_eq!(rebuilt, bytes[40..]);
    }
}
