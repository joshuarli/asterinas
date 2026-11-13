// SPDX-License-Identifier: MPL-2.0

use core::sync::atomic::Ordering;

use super::{SyscallReturn, get_ioprio::IoPrioWho};
use crate::{
    prelude::*,
    process::{UserNamespace, credentials::capabilities::CapSet, posix_thread::AsPosixThread},
    security::lsm::hooks as lsm_hooks,
};

pub(super) fn sys_ioprio_set(
    which: u32,
    who: u32,
    ioprio: u32,
    ctx: &Context,
) -> Result<SyscallReturn> {
    debug!("which = {}, who = {}, ioprio = {}", which, who, ioprio);

    let capable = |capability| {
        lsm_hooks::on_capable(lsm_hooks::CapableContext::new(
            UserNamespace::get_init_singleton().as_ref(),
            ctx.posix_thread,
            capability,
        )).is_ok()
    };
    match (ioprio >> 13) & 7 {
        1 => {
            if !capable(CapSet::SYS_ADMIN) && !capable(CapSet::SYS_NICE) {
                return_errno!(Errno::EPERM);
            }
        }
        2 | 3 => {}
        0 if ioprio & 7 == 0 => {}
        _ => return_errno!(Errno::EINVAL),
    }

    let ioprio_who = IoPrioWho::from_which_and_who(which, who, ctx)?;

    match ioprio_who {
        IoPrioWho::Thread(thread) => {
            let target = thread.as_posix_thread().unwrap();
            let same_owner = {
                let caller = ctx.posix_thread.credentials();
                let target = target.credentials();
                target.ruid() == caller.ruid() || target.ruid() == caller.euid()
            };
            if !same_owner && !capable(CapSet::SYS_NICE) {
                return_errno!(Errno::EPERM);
            }
            target.io_priority().store(ioprio & 0xffff, Ordering::Relaxed);
            Ok(SyscallReturn::Return(0))
        }
        IoPrioWho::ProcessGroup(_) => {
            return_errno!(Errno::EINVAL);
        }
        IoPrioWho::User(_) => {
            return_errno!(Errno::EINVAL);
        }
    }
}
