// SPDX-License-Identifier: MPL-2.0

//! This module offers `/proc/net` files that summarize the sockets of the network stack.
//!
//! Reference: <https://www.man7.org/linux/man-pages/man5/proc_pid_net.5.html>

use aster_util::printer::VmPrinter;

use crate::{
    fs::{
        file::{InodeType, mkmod},
        procfs::{
            StaticEntry,
            template::{
                ProcDir, ProcDirOps, ProcFile, ProcFileOps, ReaddirEntry, listed_entries_from_table,
                lookup_child_from_table, visit_listed_entries,
            },
        },
        vfs::inode::Inode,
    },
    net::socket::sockstat::socket_summary,
    prelude::*,
};

/// Represents the inode at `/proc/net`.
pub(super) struct NetDirOps;

impl NetDirOps {
    pub(super) fn new_inode(parent: Weak<dyn Inode>) -> Arc<dyn Inode> {
        ProcDir::new(Self, parent, mkmod!(a+rx))
    }

    const ENTRIES: &'static [StaticEntry] = &[
        ("sockstat", InodeType::File, SockStatFileOps::new_inode),
        ("sockstat6", InodeType::File, SockStat6FileOps::new_inode),
    ];
}

impl ProcDirOps for NetDirOps {
    fn lookup_child(&self, dir: &ProcDir<Self>, name: &str) -> Result<Arc<dyn Inode>> {
        lookup_child_from_table(name, Self::ENTRIES, |f| (f)(dir.this_weak().clone()))
            .ok_or_else(|| Error::from(Errno::ENOENT))
    }

    fn visit_entries_from_offset<'a, F>(&'a self, offset: usize, visit: F) -> Result<()>
    where
        F: FnMut(ReaddirEntry<'a>) -> Result<()>,
    {
        visit_listed_entries(offset, listed_entries_from_table(Self::ENTRIES), visit)
    }
}

/// Represents the inode at `/proc/net/sockstat`.
struct SockStatFileOps;

impl SockStatFileOps {
    fn new_inode(parent: Weak<dyn Inode>) -> Arc<dyn Inode> {
        ProcFile::new(Self, parent, mkmod!(a+r))
    }
}

impl ProcFileOps for SockStatFileOps {
    fn read_at(&self, offset: usize, writer: &mut VmWriter) -> Result<usize> {
        let summary = socket_summary();
        let mut printer = VmPrinter::new_skip(writer, offset);
        writeln!(printer, "sockets: used {}", summary.used)?;
        writeln!(
            printer,
            "TCP: inuse {} orphan {} tw {} alloc {}",
            summary.tcp_in_use_ipv4, summary.tcp_orphaned, summary.tcp_time_wait, summary.tcp_allocated,
        )?;
        writeln!(printer, "UDP: inuse {}", summary.udp_in_use)?;
        writeln!(printer, "UDPLITE: inuse 0")?;
        writeln!(printer, "RAW: inuse {}", summary.raw_in_use)?;
        writeln!(
            printer,
            "FRAG: inuse {} memory {}",
            summary.fragment_queues, summary.fragment_bytes,
        )?;
        Ok(printer.bytes_written())
    }
}

/// Represents the inode at `/proc/net/sockstat6`.
struct SockStat6FileOps;

impl SockStat6FileOps {
    fn new_inode(parent: Weak<dyn Inode>) -> Arc<dyn Inode> {
        ProcFile::new(Self, parent, mkmod!(a+r))
    }
}

impl ProcFileOps for SockStat6FileOps {
    fn read_at(&self, offset: usize, writer: &mut VmWriter) -> Result<usize> {
        let summary = socket_summary();
        let mut printer = VmPrinter::new_skip(writer, offset);
        writeln!(printer, "TCP6: inuse {}", summary.tcp_in_use_ipv6)?;
        writeln!(printer, "UDP6: inuse 0")?;
        writeln!(printer, "UDPLITE6: inuse 0")?;
        writeln!(printer, "RAW6: inuse 0")?;
        writeln!(printer, "FRAG6: inuse 0 memory 0")?;
        Ok(printer.bytes_written())
    }
}
