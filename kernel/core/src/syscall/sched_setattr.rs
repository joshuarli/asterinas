// SPDX-License-Identifier: MPL-2.0

use super::{
    SyscallReturn,
    sched_getattr::{SchedChange, change_sched_attr, read_linux_sched_attr_from_user},
};
use crate::{prelude::*, thread::Tid};

pub(super) fn sys_sched_setattr(
    tid: Tid,
    addr: Vaddr,
    flags: u32,
    ctx: &Context,
) -> Result<SyscallReturn> {
    if addr == 0 {
        return_errno_with_message!(Errno::EINVAL, "invalid user space address");
    }
    if flags != 0 {
        // Linux also has no support for any flags yet.
        return_errno_with_message!(Errno::EINVAL, "invalid flags");
    }

    let attr = read_linux_sched_attr_from_user(addr, ctx)?;
    change_sched_attr(tid, ctx, SchedChange::Attribute(attr))?;

    Ok(SyscallReturn::Return(0))
}
