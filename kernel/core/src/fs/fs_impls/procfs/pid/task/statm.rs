// SPDX-License-Identifier: MPL-2.0

use align_ext::AlignExt;
use aster_util::printer::VmPrinter;

use super::TidDirOps;
use crate::{
    fs::{
        file::mkmod,
        procfs::template::{ProcFile, ProcFileOps},
        vfs::inode::Inode,
    },
    prelude::*,
    thread::Thread,
};

pub(super) struct StatmFileOps(TidDirOps);

impl StatmFileOps {
    pub(super) fn new_inode(dir: &TidDirOps, parent: Weak<dyn Inode>) -> Arc<dyn Inode> {
        ProcFile::new(Self(dir.clone()), parent, mkmod!(a+r))
    }
}

impl ProcFileOps for StatmFileOps {
    fn owner_thread(&self) -> Option<Arc<Thread>> {
        self.0.thread()
    }

    fn read_at(&self, offset: usize, writer: &mut VmWriter) -> Result<usize> {
        let Some((_, process)) = self.0.thread_and_process() else {
            return_errno_with_message!(Errno::ESRCH, "the thread or the process does not exist");
        };
        let (size, resident, shared, text, data) = {
            let vmar = process.lock_vmar();
            if let Some(vmar) = vmar.as_ref() {
                let usage = vmar.memory_usage();
                let code = vmar.process_vm().code_range();
                let text_pages = (code.end.align_up(PAGE_SIZE) - code.start.align_down(PAGE_SIZE)) / PAGE_SIZE;
                (
                    usage.virtual_bytes / PAGE_SIZE,
                    usage.anonymous_resident_pages + usage.file_resident_pages,
                    usage.file_resident_pages,
                    text_pages,
                    vmar.private_writable_mapping_bytes() / PAGE_SIZE,
                )
            } else {
                (0, 0, 0, 0, 0)
            }
        };
        let mut printer = VmPrinter::new_skip(writer, offset);
        writeln!(printer, "{} {} {} {} 0 {} 0", size, resident, shared, text, data)?;
        Ok(printer.bytes_written())
    }
}
