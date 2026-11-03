// SPDX-License-Identifier: MPL-2.0

use ostd_pod::IntoBytes;
use smoltcp::wire::{Icmpv4DstUnreachable, Icmpv4Message, IpEndpoint, Ipv4Address};

use crate::{
    iface::wire::utils::Checksum,
    packet::{ApplicationLayer, TransportLayer, TxPacket},
};

pub(in crate::iface) const HEADER_LEN: usize = size_of::<Header>();

pub(in crate::iface) fn reply_tos(original: u8) -> u8 {
    (original & 0x1e) | 0xc0
}

pub(in crate::iface) struct QuotedUdpError<'a> {
    pub source: IpEndpoint,
    pub destination: IpEndpoint,
    pub type_: u8,
    pub code: u8,
    pub info: u32,
    pub payload: &'a [u8],
}

pub(in crate::iface) fn parse_udp_error(
    packet: &[u8],
    verify_checksum: bool,
) -> Option<QuotedUdpError<'_>> {
    if packet.len() < HEADER_LEN + 20 + 8
        || verify_checksum && Checksum::new().with_bytes(packet).finish() != u16::MAX
    {
        return None;
    }
    let type_ = packet[0];
    if !matches!((type_, packet[1]), (3, 0..=15) | (11, 0) | (12, _)) {
        return None;
    }
    let quoted = &packet[HEADER_LEN..];
    let header_len = usize::from(quoted[0] & 0x0f) * 4;
    if quoted[0] >> 4 != 4 || header_len < 20 || quoted.len() < header_len + 8
        || quoted[9] != 17 || u16::from_be_bytes([quoted[6], quoted[7]]) & 0x1fff != 0
    {
        return None;
    }
    let total_len = usize::from(u16::from_be_bytes([quoted[2], quoted[3]]));
    let udp = &quoted[header_len..];
    let udp_len = usize::from(u16::from_be_bytes([udp[4], udp[5]]));
    if udp_len < 8 || total_len < header_len + 8 {
        return None;
    }
    let source = Ipv4Address::new(quoted[12], quoted[13], quoted[14], quoted[15]);
    let destination = Ipv4Address::new(quoted[16], quoted[17], quoted[18], quoted[19]);
    let source_port = u16::from_be_bytes([udp[0], udp[1]]);
    let destination_port = u16::from_be_bytes([udp[2], udp[3]]);
    let payload_end = udp_len.min(udp.len()).min(total_len - header_len);
    Some(QuotedUdpError {
        source: IpEndpoint::new(source.into(), source_port),
        destination: IpEndpoint::new(destination.into(), destination_port),
        type_,
        code: packet[1],
        info: match (type_, packet[1]) {
            (3, 4) => u32::from(u16::from_be_bytes([packet[6], packet[7]])),
            (12, _) => u32::from(packet[4]),
            _ => 0,
        },
        payload: &udp[8..payload_end],
    })
}

pub(in crate::iface) fn emit_dst_unreachable(
    pkt: TxPacket<ApplicationLayer>,
    reason: Icmpv4DstUnreachable,
    csum: bool,
) -> TxPacket<TransportLayer> {
    let mut header = Header {
        type_: Icmpv4Message::DstUnreachable.into(),
        code: reason.into(),
        csum: 0,
        unused: 0,
    };

    if csum {
        header.csum = !Checksum::new()
            .with_bytes(header.as_bytes())
            .with_reader(pkt.reader())
            .finish();
    }

    pkt.prepend_and_pack(&header)
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Pod)]
struct Header {
    type_: u8,
    code: u8,
    csum: u16,
    unused: u32,
}

#[cfg(ktest)]
mod test {
    use alloc::vec;
    use ostd::prelude::ktest;

    use super::*;

    fn packet() -> alloc::vec::Vec<u8> {
        let mut packet = vec![0u8; 41];
        packet[0] = 3;
        packet[1] = 3;
        packet[8] = 0x45;
        packet[10..12].copy_from_slice(&33u16.to_be_bytes());
        packet[17] = 17;
        packet[20..24].copy_from_slice(&[192, 0, 2, 1]);
        packet[24..28].copy_from_slice(&[192, 0, 2, 2]);
        packet[28..30].copy_from_slice(&1234u16.to_be_bytes());
        packet[30..32].copy_from_slice(&4321u16.to_be_bytes());
        packet[32..34].copy_from_slice(&13u16.to_be_bytes());
        packet[36..41].copy_from_slice(b"probe");
        let sum = !Checksum::new().with_bytes(&packet).finish();
        packet[2..4].copy_from_slice(&sum.to_ne_bytes());
        packet
    }

    #[ktest]
    fn udp_error_preserves_endpoints_and_quoted_payload() {
        let packet = packet();
        let error = parse_udp_error(&packet, true).unwrap();
        assert_eq!(error.source.port, 1234);
        assert_eq!(error.destination.port, 4321);
        assert_eq!(error.type_, 3);
        assert_eq!(error.code, 3);
        assert_eq!(error.payload, b"probe");
    }

    #[ktest]
    fn udp_error_rejects_invalid_checksum_and_truncated_headers() {
        let packet = packet();
        assert!(parse_udp_error(&packet[..35], false).is_none());
        let mut corrupt = packet;
        corrupt[40] ^= 1;
        assert!(parse_udp_error(&corrupt, true).is_none());
        corrupt[14] = 0;
        corrupt[15] = 1;
        assert!(parse_udp_error(&corrupt, false).is_none());
    }
}
