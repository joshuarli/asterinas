// SPDX-License-Identifier: MPL-2.0

use core::sync::atomic::Ordering;

use super::SyscallReturn;
use crate::{
    prelude::*,
    process::{ProcessGroup, Uid, pid_table, posix_thread::AsPosixThread},
    sched::{SchedPolicy, UserFairPolicy},
    thread::{AsThread, Thread},
};

pub(super) enum IoPrioAccess {
    Read,
    Write,
}

pub(super) enum IoPrioWho {
    Thread(Arc<Thread>),
    ProcessGroup(Arc<ProcessGroup>),
    User(Vec<Arc<Thread>>),
}

impl IoPrioWho {
    pub(super) fn resolve(which: u32, who: u32, ctx: &Context, access: IoPrioAccess) -> Result<Self> {
        match which {
            1 => {
                let target_tid = if who == 0 { ctx.posix_thread.tid() } else { who };
                let thread = pid_table::pid_table_mut()
                    .get_thread(target_tid)
                    .ok_or_else(|| Error::new(Errno::ESRCH))?;
                Ok(Self::Thread(thread))
            }
            2 => {
                let pgid = if who == 0 { ctx.process.pgid() } else { who };
                let group = pid_table::pid_table_mut()
                    .get_process_group(&pgid)
                    .ok_or_else(|| Error::new(Errno::ESRCH))?;
                Ok(Self::ProcessGroup(group))
            }
            3 => {
                // Linux v7.2 ioprio_set uses literal UID 0; ioprio_get uses the caller's real UID.
                let uid = match access {
                    IoPrioAccess::Read if who == 0 => ctx.posix_thread.credentials().ruid(),
                    _ => Uid::new(who),
                };
                let threads: Vec<_> = pid_table::pid_table_mut()
                    .iter_threads()
                    .filter(|thread| thread.as_posix_thread().unwrap().credentials().ruid() == uid)
                    .collect();
                if threads.is_empty() {
                    return_errno!(Errno::ESRCH);
                }
                Ok(Self::User(threads))
            }
            _ => return_errno!(Errno::EINVAL),
        }
    }

    pub(super) fn threads(self) -> Vec<Arc<Thread>> {
        match self {
            Self::Thread(thread) => vec![thread],
            Self::ProcessGroup(group) => {
                let mut threads = Vec::new();
                for process in group.lock().iter() {
                    threads.extend(process.tasks().lock().as_slice().iter()
                        .map(|task| task.as_thread().unwrap().clone()));
                }
                threads
            }
            Self::User(threads) => threads,
        }
    }
}

fn effective_priority(thread: &Thread) -> u32 {
    let target = thread.as_posix_thread().unwrap();
    let priority = target.io_priority().load(Ordering::Relaxed);
    if (priority >> 13) & 7 != 0 {
        return priority;
    }
    let (policy, user) = thread.sched_attr().user_policy();
    let class = match policy {
        SchedPolicy::RealTime { .. } | SchedPolicy::Stop => 1,
        _ if user.fair_policy == UserFairPolicy::Idle => 3,
        _ => 2,
    };
    let nice = user.user_nice.value().get() as i32;
    (class << 13) | ((nice + 20) / 5) as u32
}

pub(super) fn sys_ioprio_get(which: u32, who: u32, ctx: &Context) -> Result<SyscallReturn> {
    debug!("which = {}, who = {}", which, who);
    let targets = IoPrioWho::resolve(which, who, ctx, IoPrioAccess::Read)?;
    let priority = match targets {
        IoPrioWho::Thread(thread) => thread.as_posix_thread().unwrap()
            .io_priority().load(Ordering::Relaxed),
        targets => targets.threads().iter().map(|thread| effective_priority(thread))
            .min().ok_or_else(|| Error::new(Errno::ESRCH))?,
    };
    Ok(SyscallReturn::Return(priority as _))
}
