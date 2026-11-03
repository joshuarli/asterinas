// SPDX-License-Identifier: MPL-2.0

use super::{
    SyscallReturn,
    sched_getattr::{LinuxSchedAttr, SCHED_RESET_ON_FORK, access_sched_attr_with},
};
use crate::{prelude::*, thread::Tid};

pub(super) fn sys_sched_getscheduler(tid: Tid, ctx: &Context) -> Result<SyscallReturn> {
    let (policy, user) = access_sched_attr_with(tid, ctx, |attr| Ok(attr.user_policy()))?;
    let attr = LinuxSchedAttr::try_from(policy)?.with_user_attr(user);
    let reset_on_fork = if user.reset_on_fork { SCHED_RESET_ON_FORK } else { 0 };
    Ok(SyscallReturn::Return((attr.sched_policy | reset_on_fork) as isize))
}
