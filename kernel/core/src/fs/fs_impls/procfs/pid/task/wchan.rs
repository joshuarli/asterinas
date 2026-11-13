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
    process::posix_thread::{AsPosixThread, SleepingState, alien_access::AlienAccessMode},
    thread::Thread,
};

/// Represents the inode at `/proc/[pid]/task/[tid]/wchan` (and also `/proc/[pid]/wchan`).
///
/// The blocking call site of a thread is not recorded, so a blocked thread is
/// reported by the kind of wait it is in and a runnable thread as `0`.
pub(super) struct WchanFileOps(TidDirOps);

impl WchanFileOps {
    pub(super) fn new_inode(dir: &TidDirOps, parent: Weak<dyn Inode>) -> Arc<dyn Inode> {
        // Reference: <https://elixir.bootlin.com/linux/v6.16.5/source/fs/proc/base.c#L3334>
        ProcFile::new(Self(dir.clone()), parent, mkmod!(a+r))
    }
}

impl ProcFileOps for WchanFileOps {
    fn owner_thread(&self) -> Option<Arc<Thread>> {
        self.0.thread()
    }

    fn read_at(&self, offset: usize, writer: &mut VmWriter) -> Result<usize> {
        let mut printer = VmPrinter::new_skip(writer, offset);

        let Some((thread, process)) = self.0.thread_and_process() else {
            return_errno_with_message!(Errno::ESRCH, "the thread or the process does not exist");
        };
        let posix_thread = thread.as_posix_thread().unwrap();

        let vmar_guard = process.lock_vmar();
        let permitted = posix_thread
            .check_alien_access_from(
                current_thread!().as_posix_thread().unwrap(),
                AlienAccessMode::READ_WITH_FS_CREDS,
                &vmar_guard,
            )
            .is_ok();
        drop(vmar_guard);

        let symbol = if !permitted || thread.is_exited() {
            "0"
        } else {
            match posix_thread.sleeping_state() {
                SleepingState::Running => "0",
                SleepingState::Interruptible | SleepingState::Uninterruptible => "schedule",
                SleepingState::StopBySignal => "do_signal_stop",
                SleepingState::StopByPtrace => "ptrace_stop",
            }
        };
        write!(printer, "{}", symbol)?;

        Ok(printer.bytes_written())
    }
}
