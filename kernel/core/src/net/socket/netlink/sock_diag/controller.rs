// SPDX-License-Identifier: MPL-2.0

use aster_bigtcp::{
    diagnostic::{TcpAddressFamily, TcpSocketSnapshot, TcpState},
    wire::IpAddress,
};

use super::message::SockDiagMessage;
use crate::{
    net::{iface::iter_all_ifaces, socket::netlink::{
        addr::PortNum,
        message::CMsgSegHdr,
        table::{NetlinkSockDiagProtocol, SupportedNetlinkProtocol},
    }},
    prelude::*,
};

const SOCK_DIAG_BY_FAMILY: u16 = 20;
const REQUEST: u16 = 1;
const MULTI: u16 = 2;
const ACK: u16 = 4;
const DUMP: u16 = 0x300;
const AF_INET: u8 = 2;
const AF_INET6: u8 = 10;
const IPPROTO_TCP: u8 = 6;
const REQUEST_SIZE: usize = 56;

struct Query {
    family: u8,
    protocol: u8,
    states: u32,
    source_port: u16,
    destination_port: u16,
    source: [u8; 16],
    destination: [u8; 16],
    interface: u32,
    cookie: u64,
}

fn native_u32(bytes: &[u8]) -> u32 {
    u32::from_ne_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
}

impl Query {
    fn parse(payload: &[u8]) -> core::result::Result<Self, Errno> {
        if payload.len() < 2 { return Err(Errno::EINVAL); }
        if payload[0] >= 46 { return Err(Errno::EINVAL); }
        if payload[0] != AF_INET && payload[0] != AF_INET6 { return Err(Errno::ENOENT); }
        if payload.len() < REQUEST_SIZE { return Err(Errno::EINVAL); }
        let mut source = [0; 16];
        source.copy_from_slice(&payload[12..28]);
        let mut destination = [0; 16];
        destination.copy_from_slice(&payload[28..44]);
        let mut offset = REQUEST_SIZE;
        while payload.len() - offset >= 4 {
            let len = u16::from_ne_bytes([payload[offset], payload[offset + 1]]) as usize;
            let kind = u16::from_ne_bytes([payload[offset + 2], payload[offset + 3]]) & 0x3fff;
            if len < 4 || len > payload.len() - offset { return Err(Errno::EINVAL); }
            match kind {
                1 => return Err(if len == 4 { Errno::EINVAL } else { Errno::EOPNOTSUPP }),
                2 | 3 => return Err(Errno::EOPNOTSUPP),
                _ => {}
            }
            offset = offset.saturating_add((len + 3) & !3).min(payload.len());
        }
        Ok(Self {
            family: payload[0],
            protocol: payload[1],
            states: native_u32(&payload[4..8]),
            source_port: u16::from_be_bytes([payload[8], payload[9]]),
            destination_port: u16::from_be_bytes([payload[10], payload[11]]),
            source,
            destination,
            interface: native_u32(&payload[44..48]),
            cookie: native_u32(&payload[48..52]) as u64 | ((native_u32(&payload[52..56]) as u64) << 32),
        })
    }

    fn matches(&self, socket: &TcpSocketSnapshot, dump: bool) -> bool {
        if self.family != family(socket.family) || self.interface != 0 { return false; }
        if dump {
            self.states & (1 << state(socket.state)) != 0 &&
                (self.source_port == 0 || self.source_port == socket.local.port) &&
                (self.destination_port == 0 || self.destination_port == socket.remote.port)
        } else {
            self.source_port == socket.local.port && self.destination_port == socket.remote.port &&
                self.source == address(socket.local.addr, socket.family) && self.destination == address(socket.remote.addr, socket.family)
        }
    }
}

fn family(family: TcpAddressFamily) -> u8 {
    match family { TcpAddressFamily::Ipv4 => AF_INET, TcpAddressFamily::Ipv6 => AF_INET6 }
}

fn address(address: IpAddress, family: TcpAddressFamily) -> [u8; 16] {
    match address {
        IpAddress::Ipv4(address) => {
            let mut bytes = [0; 16];
            match family {
                TcpAddressFamily::Ipv4 => bytes[..4].copy_from_slice(&address.octets()),
                TcpAddressFamily::Ipv6 if !address.is_unspecified() => {
                    bytes[10..12].copy_from_slice(&[0xff, 0xff]);
                    bytes[12..].copy_from_slice(&address.octets());
                }
                TcpAddressFamily::Ipv6 => {}
            }
            bytes
        }
        IpAddress::Ipv6(address) => address.octets(),
    }
}

fn state(state: TcpState) -> u8 {
    match state {
        TcpState::Established => 1,
        TcpState::SynSent => 2,
        TcpState::SynReceived => 3,
        TcpState::FinWait1 => 4,
        TcpState::FinWait2 => 5,
        TcpState::TimeWait => 6,
        TcpState::Closed => 7,
        TcpState::CloseWait => 8,
        TcpState::LastAck => 9,
        TcpState::Listen => 10,
        TcpState::Closing => 11,
    }
}

fn put_u16(bytes: &mut Vec<u8>, value: u16) { bytes.extend_from_slice(&value.to_ne_bytes()); }
fn put_u32(bytes: &mut Vec<u8>, value: u32) { bytes.extend_from_slice(&value.to_ne_bytes()); }

fn header(bytes: &mut Vec<u8>, kind: u16, flags: u16, seq: u32, port: u32) {
    put_u32(bytes, 0);
    put_u16(bytes, kind);
    put_u16(bytes, flags);
    put_u32(bytes, seq);
    put_u32(bytes, port);
}

fn send(port: PortNum, mut bytes: Vec<u8>) -> Result<()> {
    let len = bytes.len() as u32;
    bytes[..4].copy_from_slice(&len.to_ne_bytes());
    NetlinkSockDiagProtocol::unicast(port, SockDiagMessage(bytes))
}

fn done(request: &CMsgSegHdr, port: PortNum, error: Option<Errno>) -> Result<()> {
    let mut bytes = Vec::with_capacity(20);
    header(&mut bytes, 3, MULTI, request.seq, port);
    bytes.extend_from_slice(&error.map_or(0, |error| -(error as i32)).to_ne_bytes());
    send(port, bytes)
}

fn error(request: &CMsgSegHdr, payload: &[u8], port: PortNum, error: Option<Errno>) -> Result<()> {
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(36 + if error.is_some() { payload.len() } else { 0 }).map_err(|_| {
        Error::with_message(Errno::ENOMEM, "cannot allocate the socket diagnostic error")
    })?;
    header(&mut bytes, 2, if error.is_none() { 0x100 } else { 0 }, request.seq, port);
    bytes.extend_from_slice(&error.map_or(0, |error| -(error as i32)).to_ne_bytes());
    put_u32(&mut bytes, request.len);
    put_u16(&mut bytes, request.type_);
    put_u16(&mut bytes, request.flags);
    put_u32(&mut bytes, request.seq);
    put_u32(&mut bytes, request.pid);
    if error.is_some() { bytes.extend_from_slice(payload); }
    send(port, bytes)
}

fn reply(request: &CMsgSegHdr, port: PortNum, socket: &TcpSocketSnapshot, dump: bool) -> Result<()> {
    let mut bytes = Vec::with_capacity(96);
    header(&mut bytes, SOCK_DIAG_BY_FAMILY, if dump { MULTI } else { 0 }, request.seq, port);
    bytes.extend_from_slice(&[family(socket.family), state(socket.state), 0, 0]);
    bytes.extend_from_slice(&socket.local.port.to_be_bytes());
    bytes.extend_from_slice(&socket.remote.port.to_be_bytes());
    bytes.extend_from_slice(&address(socket.local.addr, socket.family));
    bytes.extend_from_slice(&address(socket.remote.addr, socket.family));
    put_u32(&mut bytes, 0);
    put_u32(&mut bytes, socket.cookie as u32);
    put_u32(&mut bytes, (socket.cookie >> 32) as u32);
    put_u32(&mut bytes, 0);
    put_u32(&mut bytes, socket.read_queue);
    put_u32(&mut bytes, socket.write_queue);
    put_u32(&mut bytes, if matches!(socket.state, TcpState::TimeWait | TcpState::SynReceived) { 0 } else { socket.uid });
    put_u32(&mut bytes, socket.inode as u32);
    put_u16(&mut bytes, 5);
    put_u16(&mut bytes, 8);
    bytes.extend_from_slice(&[socket.shutdown, 0, 0, 0]);
    send(port, bytes)
}

pub(super) fn handle(request: &CMsgSegHdr, payload: &[u8], port: PortNum) -> Result<()> {
    if request.flags & REQUEST == 0 || request.type_ < 16 {
        return if request.flags & ACK != 0 { error(request, payload, port, None) } else { Ok(()) };
    }
    if request.type_ != SOCK_DIAG_BY_FAMILY {
        return error(request, payload, port, Some(if request.type_ == 21 { Errno::EOPNOTSUPP } else { Errno::EINVAL }));
    }
    let query = match Query::parse(payload) {
        Ok(query) => query,
        Err(errno) => return error(request, payload, port, Some(errno)),
    };
    let dump = request.flags & DUMP == DUMP;
    if query.protocol != IPPROTO_TCP {
        return if dump { done(request, port, Some(Errno::ENOENT)) } else { error(request, payload, port, Some(Errno::ENOENT)) };
    }
    for iface in iter_all_ifaces() {
        for socket in iface.common().tcp_snapshots() {
            if !query.matches(&socket, dump) { continue; }
            if !dump && query.cookie != u64::MAX && query.cookie != socket.cookie {
                return error(request, payload, port, Some(Errno::ENOENT));
            }
            reply(request, port, &socket, dump)?;
            if !dump {
                return if request.flags & ACK != 0 { error(request, payload, port, None) } else { Ok(()) };
            }
        }
    }
    if dump { done(request, port, None) } else { error(request, payload, port, Some(Errno::ENOENT)) }
}
