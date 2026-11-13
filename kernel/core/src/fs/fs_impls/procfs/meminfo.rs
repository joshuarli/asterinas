// SPDX-License-Identifier: MPL-2.0

//! This module offers `/proc/meminfo` file support, which tells the user space
//! about the memory statistics in the entire system. The definition of the
//! fields are similar to that of Linux's but there exist differences.
//!
//! `Buffers` is zero because block I/O has no retained block-device buffer cache.
//! `SReclaimable` is zero because the slab allocator has no reclaim mechanism.
//!
//! Reference: <https://man7.org/linux/man-pages/man5/proc_meminfo.5.html>

use aster_util::printer::VmPrinter;

use crate::{
    fs::{
        file::mkmod,
        procfs::template::{ProcFile, ProcFileOps},
        vfs::inode::Inode,
    },
    prelude::*,
};

/// Represents the inode at `/proc/meminfo`.
pub(super) struct MemInfoFileOps;

impl MemInfoFileOps {
    pub(super) fn new_inode(parent: Weak<dyn Inode>) -> Arc<dyn Inode> {
        // Reference:
        // <https://elixir.bootlin.com/linux/v6.16.5/source/fs/proc/meminfo.c#L178>
        // <https://elixir.bootlin.com/linux/v6.16.5/source/fs/proc/generic.c#L549-L550>
        ProcFile::new(Self, parent, mkmod!(a+r))
    }
}

impl ProcFileOps for MemInfoFileOps {
    fn read_at(&self, offset: usize, writer: &mut VmWriter) -> Result<usize> {
        let (file_pages, shared_pages) = crate::vm::page_cache::resident_page_counts();
        let cached = (file_pages + shared_pages) * PAGE_SIZE / 1024;
        let shmem = shared_pages * PAGE_SIZE / 1024;
        let mut printer = VmPrinter::new_skip(writer, offset);

        // The total amount of physical memory available to the system.
        let total = crate::vm::mem_total();
        // An estimation of how much memory is available for starting new
        // applications, without disk operations.
        let available = osdk_frame_allocator::load_total_free_size();

        // Convert the values to KiB.
        let total = total / 1024;
        let available = available / 1024;

        // Available memory should include both free memory and cached pages that can be
        // immediately evicted from main memory. Currently, no pages can be evicted when memory is
        // allocated, resulting in the two values being reported as the same.
        writeln!(printer, "MemTotal:\t{} kB", total)?;
        writeln!(printer, "MemFree:\t{} kB", available)?;
        writeln!(printer, "MemAvailable:\t{} kB", available)?;
        writeln!(printer, "Buffers:\t0 kB")?;
        writeln!(printer, "Cached:\t{} kB", cached)?;
        writeln!(printer, "Shmem:\t{} kB", shmem)?;
        writeln!(printer, "SReclaimable:\t0 kB")?;
        writeln!(printer, "SwapTotal:\t0 kB")?;
        writeln!(printer, "SwapFree:\t0 kB")?;

        let slab = crate::vm::mem_slab() / 1024;
        writeln!(printer, "Slab:\t{} kB", slab)?;

        Ok(printer.bytes_written())
    }
}
