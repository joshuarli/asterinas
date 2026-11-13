// SPDX-License-Identifier: MPL-2.0

use super::message::GenericMessage;
use crate::{
    net::socket::netlink::{
        addr::PortNum,
        message::CMsgSegHdr,
        table::{NetlinkGenericProtocol, SupportedNetlinkProtocol},
    },
    prelude::*,
};

struct Family {
    id: u16,
    name: &'static [u8],
    version: u32,
    header_size: u32,
    max_attr: u32,
    command: u32,
    capabilities: u32,
}

const FAMILIES: &[Family] = &[Family {
    id: 16,
    name: b"nlctrl\0",
    version: 2,
    header_size: 0,
    max_attr: 0,
    command: 3,
    capabilities: 2 | 4,
}];

fn put_u16(bytes: &mut Vec<u8>, value: u16) { bytes.extend_from_slice(&value.to_ne_bytes()); }
fn put_u32(bytes: &mut Vec<u8>, value: u32) { bytes.extend_from_slice(&value.to_ne_bytes()); }

fn attr(bytes: &mut Vec<u8>, kind: u16, payload: &[u8]) {
    put_u16(bytes, (payload.len() + 4) as u16);
    put_u16(bytes, kind);
    bytes.extend_from_slice(payload);
    while bytes.len() % 4 != 0 { bytes.push(0); }
}

fn header(bytes: &mut Vec<u8>, kind: u16, flags: u16, seq: u32, port: u32) {
    put_u32(bytes, 0);
    put_u16(bytes, kind);
    put_u16(bytes, flags);
    put_u32(bytes, seq);
    put_u32(bytes, port);
}

fn finish(bytes: &mut [u8]) {
    let len = bytes.len() as u32;
    bytes[..4].copy_from_slice(&len.to_ne_bytes());
}

fn send(port: PortNum, bytes: Vec<u8>) -> Result<()> {
    NetlinkGenericProtocol::unicast(port, GenericMessage(bytes))
}

fn family_reply(family: &Family, request: &CMsgSegHdr, port: PortNum, multi: bool) -> Result<()> {
    let mut bytes = Vec::new();
    header(&mut bytes, 16, if multi { 2 } else { 0 }, request.seq, port);
    bytes.extend_from_slice(&[1, 2, 0, 0]);
    attr(&mut bytes, 2, family.name);
    attr(&mut bytes, 1, &family.id.to_ne_bytes());
    attr(&mut bytes, 3, &family.version.to_ne_bytes());
    attr(&mut bytes, 4, &family.header_size.to_ne_bytes());
    attr(&mut bytes, 5, &family.max_attr.to_ne_bytes());
    let mut operation = Vec::new();
    attr(&mut operation, 1, &family.command.to_ne_bytes());
    attr(&mut operation, 2, &family.capabilities.to_ne_bytes());
    let mut operations = Vec::new();
    attr(&mut operations, 1, &operation);
    attr(&mut bytes, 6, &operations);
    finish(&mut bytes);
    send(port, bytes)
}

fn error(request: &CMsgSegHdr, payload: &[u8], port: PortNum, errno: Option<Errno>) -> Result<()> {
    let capped = errno.is_none();
    let capacity = 36usize.checked_add(if capped { 0 } else { payload.len() })
        .and_then(|length| length.checked_add(3)).map(|length| length & !3).ok_or_else(|| {
        Error::with_message(Errno::ENOMEM, "the generic netlink error is too large")
    })?;
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(capacity).map_err(|_| {
        Error::with_message(Errno::ENOMEM, "cannot allocate the generic netlink error")
    })?;
    header(&mut bytes, 2, if capped { 0x100 } else { 0 }, request.seq, port);
    let code = errno.map_or(0, |e| -(e as i32));
    bytes.extend_from_slice(&code.to_ne_bytes());
    put_u32(&mut bytes, request.len);
    put_u16(&mut bytes, request.type_);
    put_u16(&mut bytes, request.flags);
    put_u32(&mut bytes, request.seq);
    put_u32(&mut bytes, request.pid);
    if !capped { bytes.extend_from_slice(payload); }
    finish(&mut bytes);
    while bytes.len() % 4 != 0 { bytes.push(0); }
    send(port, bytes)
}

fn lookup(attrs: &[u8]) -> core::result::Result<&'static Family, Errno> {
    let mut offset = 0;
    let mut id = None;
    let mut name = None;
    while attrs.len().saturating_sub(offset) >= 4 {
        let len = u16::from_ne_bytes([attrs[offset], attrs[offset + 1]]) as usize;
        let kind = u16::from_ne_bytes([attrs[offset + 2], attrs[offset + 3]]) & 0x3fff;
        if len < 4 || len > attrs.len() - offset { break; }
        let data = &attrs[offset + 4..offset + len];
        match kind {
            1 => {
                if data.len() < 2 { return Err(Errno::ERANGE); }
                id = Some(u16::from_ne_bytes([data[0], data[1]]));
            }
            2 => {
                let Some(end) = data.iter().position(|b| *b == 0) else { return Err(Errno::EINVAL) };
                if end > 15 { return Err(Errno::EINVAL); }
                let string_len = data.len() - usize::from(data.last() == Some(&0));
                if string_len > 15 { return Err(Errno::ERANGE); }
                name = Some(&data[..end]);
            }
            _ => (),
        }
        offset += (len + 3) & !3;
        if offset > attrs.len() { break; }
    }
    if let Some(name) = name {
        FAMILIES.iter().find(|f| &f.name[..f.name.len() - 1] == name).ok_or(Errno::ENOENT)
    } else if let Some(id) = id {
        FAMILIES.iter().find(|f| f.id == id).ok_or(Errno::ENOENT)
    } else {
        Err(Errno::EINVAL)
    }
}

pub(super) fn handle(request: &CMsgSegHdr, payload: &[u8], port: PortNum) -> Result<()> {
    if request.flags & 1 == 0 || request.type_ < 16 {
        return if request.flags & 4 != 0 { error(request, payload, port, None) } else { Ok(()) };
    }
    let Some(controller) = FAMILIES.iter().find(|family| family.id == request.type_) else {
        return error(request, payload, port, Some(Errno::ENOENT));
    };
    if payload.len() < 4 {
        return error(request, payload, port, Some(Errno::EINVAL));
    }
    if u32::from(payload[0]) != controller.command {
        return error(request, payload, port, Some(Errno::EOPNOTSUPP));
    }
    if request.flags & 0x300 == 0x300 {
        for family in FAMILIES { family_reply(family, request, port, true)?; }
        let mut done = Vec::new();
        header(&mut done, 3, 2, request.seq, port);
        put_u32(&mut done, 0);
        finish(&mut done);
        return send(port, done);
    }
    match lookup(&payload[4..]) {
        Err(err) => error(request, payload, port, Some(err)),
        Ok(family) => {
            family_reply(family, request, port, false)?;
            if request.flags & 4 != 0 { error(request, payload, port, None) } else { Ok(()) }
        }
    }
}
