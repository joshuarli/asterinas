// SPDX-License-Identifier: MPL-2.0

use core::sync::atomic::Ordering;

use aster_util::printer::VmPrinter;
use ostd::{cpu::num_cpus, util::id_set::Id};

use super::TidDirOps;
use crate::{
    fs::{
        file::mkmod,
        procfs::template::{ProcFile, ProcFileOps},
        vfs::inode::Inode,
    },
    prelude::*,
    process::{
        posix_thread::{AsPosixThread, SleepingState},
        signal::{sig_action::SigAction, sig_mask::SigMask},
    },
    thread::Thread,
    vm::vmar::RssType,
};

/// Represents the inode at `/proc/[pid]/task/[tid]/status` (and also `/proc/[pid]/status`).
/// See <https://elixir.bootlin.com/linux/v6.16.5/source/fs/proc/array.c#L148>.
/// FIXME: Some fields are not implemented yet.
///
/// Fields:
/// - Name:   The name of the process.
/// - State:  The current state of the process (e.g., R for running, S for sleeping).
/// - Tgid:   The Thread Group ID, which is the same as the process ID for the main thread.
/// - Pid:    The process ID.
/// - PPid:   The parent process ID.
/// - TracerPid: The PID of the process tracing this process, or 0 if not being traced.
/// - Uid:    Real, effective, saved set, and filesystem UIDs.
/// - Gid:    Real, effective, saved set, and filesystem GIDs.
/// - FDSize: The number of file descriptor slots currently allocated.
/// - Groups: Supplementary group IDs.
/// - VmPeak: Peak virtual memory size.
/// - VmSize: Current virtual memory size.
/// - VmLck:  Locked memory size.
/// - VmPin:  Pinned memory size.
/// - VmHWM:  Peak resident set size ("high water mark").
/// - VmRSS:  Resident set size.
/// - VmData: Size of data segment.
/// - VmStk:  Size of stack segment.
/// - VmExe:  Size of text segment.
/// - VmLib:  Shared library code size.
/// - VmPTE:  Page table entries size.
/// - VmSwap: Swapped-out virtual memory size by anonymous private pages.
/// - Threads: Number of threads in this process.
/// - SigQ:   Current signal queue size and limit.
/// - SigPnd: Threads pending signals.
/// - ShdPnd: Shared pending signals.
/// - SigBlk: Blocked signals.
/// - SigIgn: Ignored signals.
/// - SigCgt: Caught signals.
/// - CapInh: Inheritable capabilities.
/// - CapPrm: Permitted capabilities.
/// - CapEff: Effective capabilities.
/// - CapBnd: Bounding set.
/// - CapAmb: Ambient capabilities.
/// - NoNewPrivs: Whether the no-new-privileges flag is set.
/// - Seccomp: Seccomp mode.
/// - Cpus_allowed: CPUs allowed for this process.
/// - Cpus_allowed_list: List of CPUs allowed for this process.
/// - Mems_allowed: Memory nodes allowed for this process.
/// - Mems_allowed_list: List of memory nodes allowed for this process.
/// - voluntary_ctxt_switches: Number of voluntary context switches.
/// - nonvoluntary_ctxt_switches: Number of nonvoluntary context switches.
pub(super) struct StatusFileOps(TidDirOps);

impl StatusFileOps {
    pub(super) fn new_inode(dir: &TidDirOps, parent: Weak<dyn Inode>) -> Arc<dyn Inode> {
        // Reference: <https://elixir.bootlin.com/linux/v6.16.5/source/fs/proc/base.c#L3326>
        ProcFile::new(Self(dir.clone()), parent, mkmod!(a+r))
    }
}

impl ProcFileOps for StatusFileOps {
    fn owner_thread(&self) -> Option<Arc<Thread>> {
        self.0.thread()
    }

    fn read_at(&self, offset: usize, writer: &mut VmWriter) -> Result<usize> {
        let mut printer = VmPrinter::new_skip(writer, offset);

        let Some((thread, process)) = self.0.thread_and_process() else {
            return_errno_with_message!(Errno::ESRCH, "the thread or the process does not exist");
        };
        let posix_thread = thread.as_posix_thread().unwrap();
        let credentials = posix_thread.credentials();

        // According to the Linux implementation, a process's `/proc/<pid>/status`
        // is exactly the same as its main thread's `/proc/<pid>/task/<pid>/status`.
        //
        // Reference:
        // <https://elixir.bootlin.com/linux/v6.16.5/source/fs/proc/base.c#L3326>
        // <https://elixir.bootlin.com/linux/v6.16.5/source/fs/proc/base.c#L3675>

        writeln!(
            printer,
            "Name:\t{}",
            posix_thread
                .thread_name()
                .lock()
                .as_cstr()
                .to_string_lossy()
        )?;

        let state = if thread.is_exited() {
            "Z (zombie)"
        } else {
            match posix_thread.sleeping_state() {
                SleepingState::Running => "R (running)",
                SleepingState::Interruptible => "S (sleeping)",
                SleepingState::Uninterruptible => "D (disk sleep)",
                SleepingState::StopBySignal => "T (stopped)",
                SleepingState::StopByPtrace => "t (tracing stop)",
            }
        };
        writeln!(printer, "State:\t{}", state)?;

        writeln!(printer, "Tgid:\t{}", process.pid())?;
        writeln!(printer, "Pid:\t{}", posix_thread.tid())?;
        writeln!(printer, "PPid:\t{}", process.parent().pid())?;
        writeln!(
            printer,
            "TracerPid:\t{}",
            posix_thread
                .tracer()
                .map(|tracer| tracer.as_posix_thread().unwrap().tid())
                .unwrap_or(0)
        )?;

        writeln!(
            printer,
            "Uid:\t{}\t{}\t{}\t{}",
            u32::from(credentials.ruid()),
            u32::from(credentials.euid()),
            u32::from(credentials.suid()),
            u32::from(credentials.fsuid()),
        )?;
        writeln!(
            printer,
            "Gid:\t{}\t{}\t{}\t{}",
            u32::from(credentials.rgid()),
            u32::from(credentials.egid()),
            u32::from(credentials.sgid()),
            u32::from(credentials.fsgid()),
        )?;

        writeln!(
            printer,
            "FDSize:\t{}",
            posix_thread
                .file_table()
                .lock()
                .as_ref()
                .map(|file_table| file_table.read().len())
                .unwrap_or(0)
        )?;

        if let Some(vmar_ref) = process.lock_vmar().as_ref() {
            let vsize = vmar_ref.get_mappings_total_size();
            let anon = vmar_ref.get_rss_counter(RssType::Anon) * (PAGE_SIZE / 1024);
            let file = vmar_ref.get_rss_counter(RssType::File) * (PAGE_SIZE / 1024);
            let rss = anon + file;
            writeln!(
                printer,
                "VmSize:\t{} kB\nVmRSS:\t{} kB\nRssAnon:\t{} kB\nRssFile:\t{} kB",
                vsize, rss, anon, file
            )?;
        }

        writeln!(
            printer,
            "Threads:\t{}",
            process.tasks().lock().as_slice().len()
        )?;

        let (ignored, caught) = {
            let dispositions = process.sig_dispositions().lock();
            let dispositions = dispositions.lock();
            let mut ignored = SigMask::default();
            let mut caught = SigMask::default();
            for (number, action) in dispositions.iter() {
                match action {
                    SigAction::Dfl => {}
                    SigAction::Ign => ignored += number,
                    SigAction::User { .. } => caught += number,
                }
            }
            (ignored, caught)
        };
        writeln!(printer, "SigBlk:\t{:016x}", posix_thread.sig_mask())?;
        writeln!(printer, "SigIgn:\t{:016x}", ignored)?;
        writeln!(printer, "SigCgt:\t{:016x}", caught)?;

        writeln!(
            printer,
            "CapInh:\t{:016x}",
            credentials.inheritable_capset().bits()
        )?;
        writeln!(
            printer,
            "CapPrm:\t{:016x}",
            credentials.permitted_capset().bits()
        )?;
        writeln!(
            printer,
            "CapEff:\t{:016x}",
            credentials.effective_capset().bits()
        )?;
        writeln!(
            printer,
            "CapBnd:\t{:016x}",
            credentials.bounding_capset().bits()
        )?;
        writeln!(
            printer,
            "CapAmb:\t{:016x}",
            credentials.ambient_capset().bits()
        )?;
        writeln!(
            printer,
            "NoNewPrivs:\t{}",
            u8::from(credentials.no_new_privs())
        )?;

        let affinity = thread.atomic_cpu_affinity().load(Ordering::Relaxed);
        let mut mask = vec![0u32; num_cpus().div_ceil(u32::BITS as usize)];
        for cpu in affinity.iter() {
            let id = cpu.as_usize();
            mask[id / u32::BITS as usize] |= 1 << (id % u32::BITS as usize);
        }
        write!(printer, "Cpus_allowed:\t")?;
        for (index, part) in mask.iter().rev().enumerate() {
            if index != 0 {
                write!(printer, ",")?;
            }
            write!(printer, "{:08x}", part)?;
        }
        write!(printer, "\nCpus_allowed_list:\t")?;
        let mut cpus = affinity.iter().map(|cpu| cpu.as_usize()).peekable();
        let mut separator = "";
        while let Some(first) = cpus.next() {
            let mut last = first;
            while cpus.peek().is_some_and(|next| *next == last + 1) {
                last = cpus.next().unwrap();
            }
            write!(printer, "{}{}", separator, first)?;
            if last != first {
                write!(printer, "-{}", last)?;
            }
            separator = ",";
        }
        writeln!(printer)?;

        Ok(printer.bytes_written())
    }
}
