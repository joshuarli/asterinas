// SPDX-License-Identifier: MPL-2.0

use aster_util::printer::VmPrinter;
use spin::Once;

use crate::{
    fs::{
        file::{InodeType, mkmod},
        procfs::{
            StaticEntry,
            template::{
                ProcDir, ProcDirOps, ProcFile, ProcFileOps, ReaddirEntry,
                listed_entries_from_table, lookup_child_from_table, visit_listed_entries,
            },
        },
        vfs::inode::Inode,
    },
    prelude::*,
    util::random::getrandom,
};

/// Represents the inode at `/proc/sys/kernel/random`.
pub(super) struct RandomDirOps;

impl RandomDirOps {
    pub(super) fn new_inode(parent: Weak<dyn Inode>) -> Arc<dyn Inode> {
        // Reference: <https://elixir.bootlin.com/linux/v6.16.5/source/drivers/char/random.c#L1688>
        ProcDir::new(Self, parent, mkmod!(a+rx))
    }

    const STATIC_ENTRIES: &'static [StaticEntry] =
        &[("boot_id", InodeType::File, BootIdFileOps::new_inode)];
}

impl ProcDirOps for RandomDirOps {
    fn lookup_child(&self, this_dir: &ProcDir<Self>, name: &str) -> Result<Arc<dyn Inode>> {
        if let Some(child) = lookup_child_from_table(name, Self::STATIC_ENTRIES, |f| {
            (f)(this_dir.this_weak().clone())
        }) {
            return Ok(child);
        }

        return_errno_with_message!(Errno::ENOENT, "the file does not exist");
    }

    fn visit_entries_from_offset<'a, F>(&'a self, offset: usize, visit_fn: F) -> Result<()>
    where
        F: FnMut(ReaddirEntry<'a>) -> Result<()>,
    {
        visit_listed_entries(
            offset,
            listed_entries_from_table(Self::STATIC_ENTRIES),
            visit_fn,
        )
    }
}

/// Represents the inode at `/proc/sys/kernel/random/boot_id`.
struct BootIdFileOps;

impl BootIdFileOps {
    fn new_inode(parent: Weak<dyn Inode>) -> Arc<dyn Inode> {
        // Reference: <https://elixir.bootlin.com/linux/v6.16.5/source/drivers/char/random.c#L1630>
        ProcFile::new(Self, parent, mkmod!(a+r))
    }
}

/// A random version 4 UUID, generated on first use and the same until the next boot.
fn boot_id() -> &'static [u8; 16] {
    static BOOT_ID: Once<[u8; 16]> = Once::new();

    BOOT_ID.call_once(|| {
        let mut uuid = [0u8; 16];
        getrandom(&mut uuid);
        uuid[6] = (uuid[6] & 0x0f) | 0x40;
        uuid[8] = (uuid[8] & 0x3f) | 0x80;
        uuid
    })
}

impl ProcFileOps for BootIdFileOps {
    fn read_at(&self, offset: usize, writer: &mut VmWriter) -> Result<usize> {
        let mut printer = VmPrinter::new_skip(writer, offset);

        for (index, byte) in boot_id().iter().enumerate() {
            if matches!(index, 4 | 6 | 8 | 10) {
                write!(printer, "-")?;
            }
            write!(printer, "{:02x}", byte)?;
        }
        writeln!(printer)?;

        Ok(printer.bytes_written())
    }
}
