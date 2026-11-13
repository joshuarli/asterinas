// SPDX-License-Identifier: MPL-2.0

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

pub(super) struct ChildrenFileOps(TidDirOps);

impl ChildrenFileOps {
    pub(super) fn new_inode(dir: &TidDirOps, parent: Weak<dyn Inode>) -> Arc<dyn Inode> {
        ProcFile::new(Self(dir.clone()), parent, mkmod!(a+r))
    }
}

impl ProcFileOps for ChildrenFileOps {
    fn owner_thread(&self) -> Option<Arc<Thread>> {
        self.0.thread()
    }

    fn read_at(&self, offset: usize, writer: &mut VmWriter) -> Result<usize> {
        let Some((thread, process)) = self.0.thread_and_process() else {
            return_errno_with_message!(Errno::ESRCH, "the thread or the process does not exist");
        };
        let children = process.children_of_thread(&thread);
        let mut printer = VmPrinter::new_skip(writer, offset);
        for pid in children {
            write!(printer, "{} ", pid)?;
        }
        Ok(printer.bytes_written())
    }
}
