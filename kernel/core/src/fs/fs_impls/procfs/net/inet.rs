// SPDX-License-Identifier: MPL-2.0

use alloc::format;

use aster_bigtcp::{diagnostic::{TcpAddressFamily, TcpState}, wire::{IpAddress, IpEndpoint, Ipv4Address, Ipv6Address}};
use aster_util::printer::VmPrinter;

use crate::{fs::{file::mkmod, procfs::template::{ProcFile, ProcFileOps}, vfs::inode::Inode}, net::socket::ip::{proc_tcp_page, proc_udp_page}, prelude::*};

pub(super) struct InetFileOps { tcp: bool, ipv6: bool }

impl InetFileOps {
    fn new(parent: Weak<dyn Inode>, tcp: bool, ipv6: bool) -> Arc<dyn Inode> {
        ProcFile::new(Self { tcp, ipv6 }, parent, mkmod!(a+r))
    }
    pub(super) fn tcp(parent: Weak<dyn Inode>) -> Arc<dyn Inode> { Self::new(parent, true, false) }
    pub(super) fn tcp6(parent: Weak<dyn Inode>) -> Arc<dyn Inode> { Self::new(parent, true, true) }
    pub(super) fn udp(parent: Weak<dyn Inode>) -> Arc<dyn Inode> { Self::new(parent, false, false) }
    pub(super) fn udp6(parent: Weak<dyn Inode>) -> Arc<dyn Inode> { Self::new(parent, false, true) }
}

fn address(addr: IpAddress) -> String {
    match addr {
        IpAddress::Ipv4(addr) => format!("{:08X}", u32::from_ne_bytes(addr.octets())),
        IpAddress::Ipv6(addr) => {
            let bytes = addr.octets();
            format!("{:08X}{:08X}{:08X}{:08X}", u32::from_ne_bytes(bytes[0..4].try_into().unwrap()), u32::from_ne_bytes(bytes[4..8].try_into().unwrap()), u32::from_ne_bytes(bytes[8..12].try_into().unwrap()), u32::from_ne_bytes(bytes[12..16].try_into().unwrap()))
        }
    }
}

fn state(state: TcpState) -> u8 {
    match state {
        TcpState::Established => 1, TcpState::SynSent => 2, TcpState::SynReceived => 3,
        TcpState::FinWait1 => 4, TcpState::FinWait2 => 5, TcpState::TimeWait => 6,
        TcpState::Closed => 7, TcpState::CloseWait => 8, TcpState::LastAck => 9,
        TcpState::Listen => 10, TcpState::Closing => 11,
    }
}

fn row(printer: &mut VmPrinter, index: usize, local: IpEndpoint, remote: IpEndpoint, state: u8, tx: u32, rx: u32, uid: u32, inode: u64) -> Result<()> {
    writeln!(printer, "{:4}: {}:{:04X} {}:{:04X} {:02X} {:08X}:{:08X} 00:00000000 00000000 {:5} 0 {} 0 0000000000000000", index, address(local.addr), local.port, address(remote.addr), remote.port, state, tx, rx, uid, inode)?;
    Ok(())
}

impl ProcFileOps for InetFileOps {
    fn read_at(&self, offset: usize, writer: &mut VmWriter) -> Result<usize> {
        let capacity = writer.avail();
        let mut printer = VmPrinter::new_skip(writer, offset);
        writeln!(printer, "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode")?;
        let mut index = 0;
        if self.tcp {
            let mut iface = 0;
            while let Some(mut page) = proc_tcp_page(iface, 0, 128) {
                let mut pos = 0;
                loop {
                    let count = page.len();
                    for socket in page {
                        if (socket.family == TcpAddressFamily::Ipv6) != self.ipv6 { continue; }
                        row(&mut printer, index, socket.local, socket.remote, state(socket.state), socket.write_queue, socket.read_queue, socket.uid, socket.inode)?;
                        index += 1;
                        if printer.bytes_written() == capacity { return Ok(capacity); }
                    }
                    if count < 128 { break; }
                    pos += count;
                    page = proc_tcp_page(iface, pos, 128).unwrap_or_default();
                }
                iface += 1;
            }
        } else {
            let mut cursor = None;
            loop {
                let (next, page) = proc_udp_page(cursor, 128);
                let Some(next) = next else { break; };
                cursor = Some(next);
                for socket in page {
                    if matches!(socket.local.addr, IpAddress::Ipv6(_)) != self.ipv6 { continue; }
                    let unspecified = match socket.local.addr { IpAddress::Ipv4(_) => IpAddress::Ipv4(Ipv4Address::UNSPECIFIED), IpAddress::Ipv6(_) => IpAddress::Ipv6(Ipv6Address::UNSPECIFIED) };
                    let remote = socket.remote.unwrap_or(IpEndpoint::new(unspecified, 0));
                    row(&mut printer, index, socket.local, remote, if socket.remote.is_some() { 1 } else { 7 }, socket.write_queue, socket.read_queue, socket.uid, socket.inode)?;
                    index += 1;
                    if printer.bytes_written() == capacity { return Ok(capacity); }
                }
            }
        }
        Ok(printer.bytes_written())
    }
}
