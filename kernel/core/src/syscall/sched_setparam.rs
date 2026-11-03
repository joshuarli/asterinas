// SPDX-License-Identifier: MPL-2.0

use ostd::mm::VmIo;

use super::{SyscallReturn, sched_getattr::{SchedChange, change_sched_attr}};
use crate::{prelude::*, thread::Tid};

pub(super) fn sys_sched_setparam(tid: Tid, addr: Vaddr, ctx: &Context) -> Result<SyscallReturn> {
    if addr == 0 {
        return_errno_with_message!(Errno::EINVAL, "invalid user space address");
    }

    let prio: i32 = ctx.user_space().read_val(addr)?;

    let priority = u32::try_from(prio)
        .map_err(|_| Error::with_message(Errno::EINVAL, "invalid scheduling priority"))?;
    change_sched_attr(tid, ctx, SchedChange::Priority(priority))?;

    Ok(SyscallReturn::Return(0))
}
