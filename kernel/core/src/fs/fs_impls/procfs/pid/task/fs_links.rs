// SPDX-License-Identifier: MPL-2.0

use super::TidDirOps;
use crate::{
    fs::{
        file::mkmod,
        procfs::template::{ProcSym, ProcSymOps},
        vfs::inode::{Inode, SymbolicLink},
    },
    prelude::*,
    process::posix_thread::{AsPosixThread, alien_access::AlienAccessMode},
    thread::Thread,
};

enum FsLink {
    Cwd,
    Root,
}

pub(super) struct FsLinkOps(TidDirOps, FsLink);

impl FsLinkOps {
    pub(super) fn new_cwd_inode(dir: &TidDirOps, parent: Weak<dyn Inode>) -> Arc<dyn Inode> {
        ProcSym::new(Self(dir.clone(), FsLink::Cwd), parent, mkmod!(a+rwx))
    }

    pub(super) fn new_root_inode(dir: &TidDirOps, parent: Weak<dyn Inode>) -> Arc<dyn Inode> {
        ProcSym::new(Self(dir.clone(), FsLink::Root), parent, mkmod!(a+rwx))
    }
}

impl ProcSymOps for FsLinkOps {
    fn owner_thread(&self) -> Option<Arc<Thread>> {
        self.0.thread()
    }

    fn read_link(&self) -> Result<SymbolicLink> {
        let Some((thread, process)) = self.0.thread_and_process() else {
            return_errno_with_message!(Errno::ESRCH, "the thread does not exist");
        };
        let vmar_guard = process.lock_vmar();
        let posix_thread = thread.as_posix_thread().unwrap();
        posix_thread
            .check_alien_access_from(
                current_thread!().as_posix_thread().unwrap(),
                AlienAccessMode::READ_WITH_FS_CREDS,
                &vmar_guard,
            )
            .map_err(|_| Error::with_message(Errno::EACCES, "alien access is denied"))?;
        if thread.is_exited() {
            return_errno_with_message!(Errno::ENOENT, "the thread has exited");
        }
        let fs = posix_thread.read_fs();
        let resolver = fs.resolver().read();
        let path = match self.1 {
            FsLink::Cwd => resolver.cwd().clone(),
            FsLink::Root => resolver.root().clone(),
        };
        Ok(SymbolicLink::Path(path))
    }
}
