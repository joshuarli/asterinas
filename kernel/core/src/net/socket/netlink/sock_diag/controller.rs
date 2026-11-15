// SPDX-License-Identifier: MPL-2.0

use aster_bigtcp::{
    iface::UdpSnapshotCursor,
    socket::{TCP_RECV_BUF_LEN, TCP_SEND_BUF_LEN, UDP_RECV_PAYLOAD_LEN, UDP_SEND_PAYLOAD_LEN},
    diagnostic::{TcpAddressFamily, TcpSocketSnapshot, TcpState, UdpSocketSnapshot, tcp_table_generation},
    wire::IpAddress,
};

use super::message::SockDiagMessage;
use crate::{
    net::{iface::{iter_all_ifaces, network_registry}, socket::netlink::{
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
const IPPROTO_UDP: u8 = 17;
const ENTRY_SIZE: usize = 168;
const EXT_MEMINFO: u8 = 1 << 0;
const EXT_SKMEMINFO: u8 = 1 << 6;
const TCP_CLOSE: u8 = 7;
const TCP_LISTEN: u8 = 10;
const REQUEST_SIZE: usize = 56;

pub(super) struct Query {
    family: u8,
    protocol: u8,
    extensions: u8,
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
            extensions: payload[2],
            states: native_u32(&payload[4..8]),
            source_port: u16::from_be_bytes([payload[8], payload[9]]),
            destination_port: u16::from_be_bytes([payload[10], payload[11]]),
            source,
            destination,
            interface: native_u32(&payload[44..48]),
            cookie: native_u32(&payload[48..52]) as u64 | ((native_u32(&payload[52..56]) as u64) << 32),
        })
    }

    fn matches(&self, socket: &Entry, dump: bool) -> bool {
        if self.family != socket.family { return false; }
        if self.protocol == IPPROTO_TCP && self.interface != 0 { return false; }
        if dump {
            self.states & (1 << socket.state) != 0 &&
                (self.source_port == 0 || self.source_port == socket.local_port) &&
                (self.destination_port == 0 || self.destination_port == socket.remote_port)
        } else {
            self.source_port == socket.local_port && self.destination_port == socket.remote_port &&
                self.source == socket.local && self.destination == socket.remote
        }
    }
}

struct Entry {
    family: u8,
    state: u8,
    local_port: u16,
    remote_port: u16,
    local: [u8; 16],
    remote: [u8; 16],
    interface: u32,
    cookie: u64,
    read_queue: u32,
    write_queue: u32,
    uid: u32,
    inode: u32,
    shutdown: u8,
    v6only: Option<bool>,
    memory: Memory,
}

struct Memory {
    receive_used: u32,
    receive_capacity: u32,
    send_used: u32,
    send_capacity: u32,
    send_queued: u32,
}

impl Entry {
    fn from_tcp(socket: &TcpSocketSnapshot) -> Self {
        let family = family(socket.family);
        let state = state(socket.state);
        let local = address(socket.local.addr, socket.family);
        Self {
            family, state,
            local_port: socket.local.port,
            remote_port: socket.remote.port,
            local,
            remote: address(socket.remote.addr, socket.family),
            interface: 0,
            cookie: socket.cookie,
            read_queue: socket.read_queue,
            write_queue: socket.write_queue,
            uid: if matches!(socket.state, TcpState::TimeWait | TcpState::SynReceived) { 0 } else { socket.uid },
            inode: socket.inode as u32,
            shutdown: socket.shutdown,
            v6only: v6only(family, state, &local),
            memory: Memory {
                receive_used: if socket.state == TcpState::Listen { 0 } else { socket.read_queue },
                receive_capacity: TCP_RECV_BUF_LEN as u32,
                send_used: if socket.state == TcpState::Listen { 0 } else { socket.write_queue },
                send_capacity: TCP_SEND_BUF_LEN as u32,
                send_queued: if socket.state == TcpState::Listen { 0 } else { socket.write_queue },
            },
        }
    }

    fn from_udp(socket: &UdpSocketSnapshot) -> Self {
        let remote = socket.remote.filter(|remote| remote.port != 0);
        Self {
            family: AF_INET,
            state: if remote.is_some() { 1 } else { TCP_CLOSE },
            local_port: socket.local.port,
            remote_port: remote.map_or(0, |remote| remote.port),
            local: address(socket.local.addr, TcpAddressFamily::Ipv4),
            remote: remote.map_or([0; 16], |remote| address(remote.addr, TcpAddressFamily::Ipv4)),
            interface: socket.device.unwrap_or(0),
            cookie: socket.cookie,
            read_queue: socket.read_queue,
            write_queue: socket.write_queue,
            uid: socket.uid,
            inode: socket.inode as u32,
            shutdown: 0,
            v6only: None,
            memory: Memory {
                receive_used: socket.read_queue,
                receive_capacity: UDP_RECV_PAYLOAD_LEN as u32,
                send_used: socket.write_queue,
                send_capacity: UDP_SEND_PAYLOAD_LEN as u32,
                send_queued: 0,
            },
        }
    }
}

fn v6only(family: u8, state: u8, local: &[u8; 16]) -> Option<bool> {
    (family == AF_INET6 && matches!(state, TCP_CLOSE | TCP_LISTEN)).then(|| local.iter().any(|byte| *byte != 0))
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
    NetlinkSockDiagProtocol::unicast(port, SockDiagMessage::Single(bytes))
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

fn reply(request: &CMsgSegHdr, port: PortNum, socket: &Entry, dump: bool, extensions: u8) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(ENTRY_SIZE);
    header(&mut bytes, SOCK_DIAG_BY_FAMILY, if dump { MULTI } else { 0 }, request.seq, port);
    bytes.extend_from_slice(&[socket.family, socket.state, 0, 0]);
    bytes.extend_from_slice(&socket.local_port.to_be_bytes());
    bytes.extend_from_slice(&socket.remote_port.to_be_bytes());
    bytes.extend_from_slice(&socket.local);
    bytes.extend_from_slice(&socket.remote);
    put_u32(&mut bytes, socket.interface);
    put_u32(&mut bytes, socket.cookie as u32);
    put_u32(&mut bytes, (socket.cookie >> 32) as u32);
    put_u32(&mut bytes, 0);
    put_u32(&mut bytes, socket.read_queue);
    put_u32(&mut bytes, socket.write_queue);
    put_u32(&mut bytes, socket.uid);
    put_u32(&mut bytes, socket.inode);
    put_u16(&mut bytes, 5);
    put_u16(&mut bytes, 8);
    bytes.extend_from_slice(&[socket.shutdown, 0, 0, 0]);
    if let Some(only) = socket.v6only {
        put_u16(&mut bytes, 5);
        put_u16(&mut bytes, 11);
        bytes.extend_from_slice(&[only as u8, 0, 0, 0]);
    }
    let memory = &socket.memory;
    if extensions & EXT_MEMINFO != 0 {
        put_u16(&mut bytes, 20);
        put_u16(&mut bytes, 1);
        for value in [memory.receive_used, memory.send_queued, 0, memory.send_used] { put_u32(&mut bytes, value); }
    }
    if extensions & EXT_SKMEMINFO != 0 {
        put_u16(&mut bytes, 40);
        put_u16(&mut bytes, 7);
        for value in [memory.receive_used, memory.receive_capacity, memory.send_used, memory.send_capacity,
                      0, memory.send_queued, 0, 0, 0] {
            put_u32(&mut bytes, value);
        }
    }
    let len = bytes.len() as u32;
    bytes[..4].copy_from_slice(&len.to_ne_bytes());
    bytes
}

pub(super) fn handle(request: &CMsgSegHdr, payload: &[u8], port: PortNum) -> Result<()> {
    if request.flags & REQUEST == 0 || request.type_ < 16 {
        return if request.flags & ACK != 0 { error(request, payload, port, None) } else { Ok(()) };
    }
    if request.type_ != SOCK_DIAG_BY_FAMILY {
        return error(request, payload, port, Some(if request.type_ == 21 { Errno::EOPNOTSUPP } else { Errno::EINVAL }));
    }
    if payload.first() == Some(&16) { return handle_netlink(request, payload, port); }
    let query = match Query::parse(payload) {
        Ok(query) => query,
        Err(errno) => return error(request, payload, port, Some(errno)),
    };
    let dump = request.flags & DUMP == DUMP;
    if query.protocol != IPPROTO_TCP && !(dump && query.protocol == IPPROTO_UDP) {
        return if dump { done(request, port, Some(Errno::ENOENT)) } else { error(request, payload, port, Some(Errno::ENOENT)) };
    }
    if dump {
        let mut cursor = DumpCursor {
            query, request: *request, port, iface: 0, offset: 0,
            generation: tcp_table_generation(), udp_cursor: None, finished: false,
        };
        let bytes = cursor.packet();
        return NetlinkSockDiagProtocol::unicast(port, SockDiagMessage::Dump(Mutex::new(super::message::Dump {
            bytes, cursor,
        })));
    }
    for iface in iter_all_ifaces() {
        let mut offset = 0;
        loop {
            let page = iface.common().tcp_snapshots(offset, 128);
            let count = page.len();
            for socket in page {
                let socket = Entry::from_tcp(&socket);
                if !query.matches(&socket, false) { continue; }
                if query.cookie != u64::MAX && query.cookie != socket.cookie {
                    return error(request, payload, port, Some(Errno::ENOENT));
                }
                send(port, reply(request, port, &socket, false, query.extensions))?;
                return if request.flags & ACK != 0 { error(request, payload, port, None) } else { Ok(()) };
            }
            if count < 128 { break; }
            offset += count;
        }
    }
    error(request, payload, port, Some(Errno::ENOENT))
}

fn handle_netlink(request: &CMsgSegHdr, payload: &[u8], port: PortNum) -> Result<()> {
    use crate::net::socket::proc_registry::{self, ProcSocket};

    if payload.len() < 20 { return error(request, payload, port, Some(Errno::EINVAL)); }
    let protocol = payload[1];
    let inode = native_u32(&payload[4..8]);
    let show = native_u32(&payload[8..12]);
    let cookie = native_u32(&payload[12..16]) as u64 | ((native_u32(&payload[16..20]) as u64) << 32);
    let dump = request.flags & DUMP == DUMP;
    let mut packets = Vec::new();
    let mut bytes = Vec::new();
    let mut cursor = None;
    loop {
        let (next, page) = proc_registry::page(cursor, 128);
        let Some(next) = next else { break; };
        cursor = Some(next);
        for socket in page {
            let ProcSocket::Netlink { inode: socket_inode, protocol: socket_protocol, port: socket_port,
                groups, kind, connected, dst_port, dst_group, recv_used, recv_buf, send_buf } = socket else { continue; };
            if protocol != 255 && protocol as u32 != socket_protocol { continue; }
            if !dump && (inode != socket_inode as u32 || (cookie != u64::MAX && cookie != socket_inode)) { continue; }
            let mut entry = Vec::new();
            header(&mut entry, SOCK_DIAG_BY_FAMILY, if dump { MULTI } else { 0 }, request.seq, port);
            entry.extend_from_slice(&[16, kind, socket_protocol as u8, connected as u8]);
            for value in [socket_port, dst_port, dst_group, socket_inode as u32, socket_inode as u32, (socket_inode >> 32) as u32] {
                put_u32(&mut entry, value);
            }
            if show & 1 != 0 {
                put_u16(&mut entry, 40);
                put_u16(&mut entry, 0);
                for value in [recv_used, recv_buf, 0, send_buf, 0, 0, 0, 0, 0] { put_u32(&mut entry, value); }
            }
            if show & 2 != 0 {
                put_u16(&mut entry, 8);
                put_u16(&mut entry, 1);
                put_u32(&mut entry, groups);
            }
            let len = entry.len() as u32;
            entry[..4].copy_from_slice(&len.to_ne_bytes());
            if !dump {
                send(port, entry)?;
                return if request.flags & ACK != 0 { error(request, payload, port, None) } else { Ok(()) };
            }
            if bytes.len() + entry.len() + 20 > DUMP_PACKET_SIZE {
                packets.push(core::mem::take(&mut bytes));
            }
            bytes.extend_from_slice(&entry);
        }
    }
    if !dump { return error(request, payload, port, Some(Errno::ENOENT)); }
    let mut end = Vec::new();
    header(&mut end, 3, MULTI, request.seq, port);
    put_u32(&mut end, 0);
    end[..4].copy_from_slice(&20u32.to_ne_bytes());
    bytes.extend_from_slice(&end);
    packets.push(bytes);
    NetlinkSockDiagProtocol::unicast(port, SockDiagMessage::NetlinkDump(Mutex::new(super::message::NetlinkDump { packets, index: 0 })))
}

pub(super) const DUMP_PACKET_SIZE: usize = 16384;

pub(super) struct DumpCursor {
    query: Query,
    request: CMsgSegHdr,
    port: PortNum,
    iface: usize,
    offset: usize,
    generation: u64,
    udp_cursor: Option<UdpSnapshotCursor>,
    pub(super) finished: bool,
}

impl DumpCursor {
    pub(super) fn packet(&mut self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(DUMP_PACKET_SIZE);
        if self.query.protocol == IPPROTO_UDP {
            loop {
                let room = (DUMP_PACKET_SIZE - bytes.len() - 20) / ENTRY_SIZE;
                if room == 0 { return bytes; }
                let (next, page) = if self.query.family == AF_INET {
                    network_registry().udp_snapshot_page(self.udp_cursor, room.min(128))
                } else {
                    (None, Vec::new())
                };
                let Some(next) = next else {
                    let mut end = Vec::with_capacity(20);
                    header(&mut end, 3, MULTI, self.request.seq, self.port);
                    put_u32(&mut end, 0);
                    end[..4].copy_from_slice(&20u32.to_ne_bytes());
                    bytes.extend_from_slice(&end);
                    self.finished = true;
                    return bytes;
                };
                self.udp_cursor = Some(next);
                for socket in page {
                    let socket = Entry::from_udp(&socket);
                    if self.query.matches(&socket, true) {
                        bytes.extend_from_slice(&reply(&self.request, self.port, &socket, true, self.query.extensions));
                    }
                }
            }
        }
        if self.query.states == 0 { self.iface = iter_all_ifaces().len(); }
        loop {
            let Some(iface) = iter_all_ifaces().nth(self.iface) else {
                let mut end = Vec::with_capacity(20);
                let flags = MULTI | if self.generation == tcp_table_generation() { 0 } else { 0x10 };
                header(&mut end, 3, flags, self.request.seq, self.port);
                put_u32(&mut end, 0);
                end[..4].copy_from_slice(&20u32.to_ne_bytes());
                bytes.extend_from_slice(&end);
                self.finished = true;
                return bytes;
            };
            let room = (DUMP_PACKET_SIZE - bytes.len() - 20) / ENTRY_SIZE;
            if room == 0 { return bytes; }
            let page = iface.common().tcp_snapshots(self.offset, room.min(128));
            let count = page.len();
            self.offset += count;
            if count < room.min(128) {
                self.iface += 1;
                self.offset = 0;
            }
            for socket in page {
                let socket = Entry::from_tcp(&socket);
                if self.query.matches(&socket, true) {
                    bytes.extend_from_slice(&reply(&self.request, self.port, &socket, true, self.query.extensions));
                }
            }
        }
    }
}
