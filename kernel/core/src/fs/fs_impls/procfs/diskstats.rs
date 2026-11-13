// SPDX-License-Identifier: MPL-2.0

//! Request accounting for registered block devices.

use aster_util::printer::VmPrinter;

use crate::{
    fs::{
        file::mkmod,
        procfs::template::{ProcFile, ProcFileOps},
        vfs::inode::Inode,
    },
    prelude::*,
};

pub(super) struct DiskStatsFileOps;

impl DiskStatsFileOps {
    pub(super) fn new_inode(parent: Weak<dyn Inode>) -> Arc<dyn Inode> {
        ProcFile::new(Self, parent, mkmod!(a+r))
    }
}

impl ProcFileOps for DiskStatsFileOps {
    fn read_at(&self, offset: usize, writer: &mut VmWriter) -> Result<usize> {
        let devices = aster_block::collect_all();
        let mut snapshots = Vec::with_capacity(devices.len());
        for device in devices {
            let Some(stats) = device.io_stats() else {
                return_errno_with_message!(Errno::EOPNOTSUPP, "block device statistics unavailable");
            };
            snapshots.push((device, stats));
        }
        let mut printer = VmPrinter::new_skip(writer, offset);
        for (device, stats) in snapshots {
            let id = device.id();
            writeln!(printer, "{} {} {} {} {} {} {} {} {} {} {} {} {} {}",
                id.major().get(), id.minor().get(), device.name(),
                stats.reads, stats.reads_merged, stats.sectors_read, stats.read_ms,
                stats.writes, stats.writes_merged, stats.sectors_written, stats.write_ms,
                stats.in_flight, stats.io_ms, stats.weighted_io_ms)?;
        }
        Ok(printer.bytes_written())
    }
}
