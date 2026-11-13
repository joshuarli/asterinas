// SPDX-License-Identifier: MPL-2.0

//! The supported block I/O counters in `/proc/vmstat`.

use aster_util::printer::VmPrinter;

use crate::{
    fs::{
        file::mkmod,
        procfs::template::{ProcFile, ProcFileOps},
        vfs::inode::Inode,
    },
    prelude::*,
};

pub(super) struct VmStatFileOps;

impl VmStatFileOps {
    pub(super) fn new_inode(parent: Weak<dyn Inode>) -> Arc<dyn Inode> {
        ProcFile::new(Self, parent, mkmod!(a+r))
    }
}

impl ProcFileOps for VmStatFileOps {
    fn read_at(&self, offset: usize, writer: &mut VmWriter) -> Result<usize> {
        let (read_sectors, write_sectors) = aster_block::stats::submitted_sectors();
        let mut printer = VmPrinter::new_skip(writer, offset);
        writeln!(printer, "pgpgin {}", read_sectors / 2)?;
        writeln!(printer, "pgpgout {}", write_sectors / 2)?;
        // Asterinas does not support swap.
        writeln!(printer, "pswpin 0")?;
        writeln!(printer, "pswpout 0")?;
        Ok(printer.bytes_written())
    }
}
