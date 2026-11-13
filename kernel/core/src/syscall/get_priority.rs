// SPDX-License-Identifier: MPL-2.0

use super::SyscallReturn;
use crate::{
    prelude::*,
    process::{Pgid, Uid, pid_table, posix_thread::AsPosixThread},
    thread::{AsThread, Thread, Tid},
};

pub(super) fn sys_get_priority(which: i32, who: u32, ctx: &Context) -> Result<SyscallReturn> {
    let target = PriorityTarget::new(which, who, ctx)?;
    let threads = get_threads(target)?;
    let nice = threads.iter()
        .map(|thread| thread.sched_attr().user().user_nice.value().get())
        .min().ok_or_else(|| Error::new(Errno::ESRCH))?;
    Ok(SyscallReturn::Return((20 - nice as i32) as _))
}

pub(super) fn get_threads(target: PriorityTarget) -> Result<Vec<Arc<Thread>>> {
    let threads = match target {
        PriorityTarget::Thread(tid) => {
            let thread = pid_table::pid_table_mut().get_thread(tid)
                .ok_or_else(|| Error::new(Errno::ESRCH))?;
            vec![thread]
        }
        PriorityTarget::ProcessGroup(pgid) => {
            let group = pid_table::pid_table_mut().get_process_group(&pgid)
                .ok_or_else(|| Error::new(Errno::ESRCH))?;
            let mut threads = Vec::new();
            for process in group.lock().iter() {
                threads.extend(process.tasks().lock().as_slice().iter()
                    .map(|task| task.as_thread().unwrap().clone()));
            }
            threads
        }
        PriorityTarget::User(uid) => pid_table::pid_table_mut().iter_threads()
            .filter(|thread| thread.as_posix_thread().unwrap().credentials().ruid() == uid)
            .collect(),
    };
    if threads.is_empty() {
        return_errno!(Errno::ESRCH);
    }
    Ok(threads)
}

#[derive(Debug)]
pub(super) enum PriorityTarget {
    Thread(Tid),
    ProcessGroup(Pgid),
    User(Uid),
}

impl PriorityTarget {
    pub(super) fn new(which: i32, who: u32, ctx: &Context) -> Result<Self> {
        match which {
            0 => Ok(Self::Thread(if who == 0 { ctx.posix_thread.tid() } else { who })),
            1 => Ok(Self::ProcessGroup(if who == 0 { ctx.process.pgid() } else { who })),
            2 => Ok(Self::User(if who == 0 { ctx.posix_thread.credentials().ruid() } else { Uid::new(who) })),
            _ => return_errno!(Errno::EINVAL),
        }
    }
}
