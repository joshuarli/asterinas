// SPDX-License-Identifier: MPL-2.0

use aster_util::printer::VmPrinter;

use crate::{fs::{file::mkmod, procfs::template::{ProcFile, ProcFileOps}, vfs::inode::Inode}, net::socket::{proc_registry::{self, ProcSocket}, unix::UnixSocketAddr}, prelude::*};

pub(super) struct LocalFileOps { unix: bool }

impl LocalFileOps {
    pub(super) fn unix(parent: Weak<dyn Inode>) -> Arc<dyn Inode> { ProcFile::new(Self { unix: true }, parent, mkmod!(a+r)) }
    pub(super) fn netlink(parent: Weak<dyn Inode>) -> Arc<dyn Inode> { ProcFile::new(Self { unix: false }, parent, mkmod!(a+r)) }
}

impl ProcFileOps for LocalFileOps {
    fn read_at(&self, offset: usize, writer: &mut VmWriter) -> Result<usize> {
        let capacity = writer.avail();
        let mut printer = VmPrinter::new_skip(writer, offset);
        if self.unix {
            writeln!(printer, "Num       RefCount Protocol Flags    Type St Inode Path")?;
        } else {
            writeln!(printer, "sk       Eth Pid        Groups   Rmem     Wmem     Dump  Locks    Drops    Inode")?;
        }
        let mut cursor = None;
        loop {
            let (next, page) = proc_registry::page(cursor, 64);
            let Some(next) = next else { break; };
            cursor = Some(next);
            for socket in page {
                match socket {
                    ProcSocket::Unix { inode, kind, state, listening, addr, .. } if self.unix => {
                        write!(printer, "0000000000000000: 00000000 00000000 {:08X} {:04X} {:02X} {}", if listening { 0x10000 } else { 0 }, kind, state, inode)?;
                        match addr {
                            UnixSocketAddr::Unnamed => {},
                            UnixSocketAddr::Path(path) => {
                                printer.write_bytes(b" ").map_err(|_| Error::from(Errno::EFAULT))?;
                                printer.write_bytes(path.to_bytes()).map_err(|_| Error::from(Errno::EFAULT))?;
                            },
                            UnixSocketAddr::Abstract(name) => {
                                printer.write_bytes(b" @").map_err(|_| Error::from(Errno::EFAULT))?;
                                for byte in name.iter() {
                                    printer.write_bytes(&[if *byte == 0 { b'@' } else { *byte }]).map_err(|_| Error::from(Errno::EFAULT))?;
                                }
                            },
                        }
                        writeln!(printer)?;
                    },
                    ProcSocket::Netlink { inode, protocol, port, groups, .. } if !self.unix && port != 0 => {
                        writeln!(printer, "0000000000000000 {} {} {:08x} 0 0 0 0 0 {}", protocol, port, groups, inode)?;
                    },
                    _ => {},
                }
                if printer.bytes_written() == capacity { return Ok(capacity); }
            }
        }
        Ok(printer.bytes_written())
    }
}
