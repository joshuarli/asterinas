// SPDX-License-Identifier: MPL-2.0

use super::SyscallReturn;
use crate::{
    prelude::*,
    process::{ResourceType::RLIMIT_NICE, UserNamespace, credentials::capabilities::CapSet, posix_thread::AsPosixThread},
    sched::{Nice, SchedPolicy, UserFairPolicy},
    security::lsm::hooks as lsm_hooks,
    syscall::get_priority::{PriorityTarget, get_processes},
};

pub(super) fn sys_set_priority(
    which: i32,
    who: u32,
    prio: i32,
    ctx: &Context,
) -> Result<SyscallReturn> {
    let prio_target = PriorityTarget::new(which, who, ctx)?;
    let new_nice: Nice = {
        let nice_raw = prio.clamp(
            Nice::MIN.value().get() as i32,
            Nice::MAX.value().get() as i32,
        ) as i8;
        nice_raw.try_into().unwrap()
    };

    debug!(
        "set_priority prio_target: {:?}, new_nice: {:?}",
        prio_target, new_nice
    );

    let processes = get_processes(prio_target)?;
    for process in processes.iter() {
        let thread = process.main_thread();
        let same_owner = {
            let caller = ctx.posix_thread.credentials();
            let target = thread.as_posix_thread().unwrap().credentials();
            caller.euid() == target.ruid() || caller.euid() == target.euid()
        };
        if !same_owner {
            let namespace = process.user_ns().lock().clone();
            lsm_hooks::on_capable(lsm_hooks::CapableContext::new(
                namespace.as_ref(),
                ctx.posix_thread,
                CapSet::SYS_NICE,
            ))?;
        }
        let privileged = lsm_hooks::on_capable(lsm_hooks::CapableContext::new(
            UserNamespace::get_init_singleton().as_ref(),
            ctx.posix_thread,
            CapSet::SYS_NICE,
        )).is_ok();
        let limit = process.resource_limits().get_rlimit(RLIMIT_NICE).get_cur();
        thread.sched_attr().update_user_policy(|policy, mut user| {
            if new_nice < user.user_nice
                && (20 - i64::from(new_nice.value().get())) as u64 > limit
                && !privileged
            {
                return_errno!(Errno::EACCES);
            }
            user.user_nice = new_nice;
            let policy = match policy {
                SchedPolicy::Fair(_) if user.fair_policy != UserFairPolicy::Idle => SchedPolicy::Fair(new_nice),
                policy => policy,
            };
            Ok((policy, user, ()))
        })?;
    }

    Ok(SyscallReturn::Return(0))
}
