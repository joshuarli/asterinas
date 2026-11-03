// SPDX-License-Identifier: MPL-2.0

use ostd::mm::VmIo;

use super::{
    SyscallReturn,
    sched_getattr::{LinuxSchedAttr, SCHED_RESET_ON_FORK, SchedChange, change_sched_attr},
};
use crate::{prelude::*, thread::Tid};

pub(super) fn sys_sched_setscheduler(
    tid: Tid,
    policy: i32,
    addr: Vaddr,
    ctx: &Context,
) -> Result<SyscallReturn> {
    if addr == 0 {
        return_errno_with_message!(Errno::EINVAL, "invalid user space address");
    }

    let prio = ctx.user_space().read_val(addr)?;

    let reset_on_fork = policy as u32 & SCHED_RESET_ON_FORK != 0;
    let attr = LinuxSchedAttr {
        sched_policy: policy as u32 & !SCHED_RESET_ON_FORK,
        sched_flags: u64::from(reset_on_fork),
        sched_priority: prio,
        ..Default::default()
    };

    change_sched_attr(tid, ctx, SchedChange::Policy(attr))?;

    Ok(SyscallReturn::Return(0))
}
