// SPDX-License-Identifier: MPL-2.0

//! Access control for the kernel message buffer.
//!
//! Reference: <https://elixir.bootlin.com/linux/v6.16.5/source/kernel/printk/printk.c#L1260>
//! (`check_syslog_permissions`).

use crate::{
    prelude::*,
    process::{UserNamespace, credentials::capabilities::CapSet, posix_thread::AsPosixThread},
    security::lsm::hooks as lsm_hooks,
};

/// `SYSLOG_ACTION_READ_ALL`: reads the whole buffer without consuming it.
pub(crate) const SYSLOG_ACTION_READ_ALL: i32 = 3;

/// `SYSLOG_ACTION_SIZE_BUFFER`: returns the capacity of the buffer.
pub(crate) const SYSLOG_ACTION_SIZE_BUFFER: i32 = 10;

/// Linux's default when `CONFIG_SECURITY_DMESG_RESTRICT` is unset.
const DMESG_RESTRICT: bool = false;

/// Returns whether reading the kernel message buffer needs `CAP_SYSLOG`.
pub(crate) fn dmesg_restrict() -> bool {
    DMESG_RESTRICT
}

/// Checks whether the current thread may perform the `syslog` action `action`.
///
/// Reading the buffer is open to everyone while `dmesg_restrict` is clear; every other action,
/// and every action while it is set, needs `CAP_SYSLOG` (or the historical `CAP_SYS_ADMIN`).
pub(crate) fn check_syslog_permissions(action: i32) -> Result<()> {
    let readable_by_all = matches!(action, SYSLOG_ACTION_READ_ALL | SYSLOG_ACTION_SIZE_BUFFER);
    if readable_by_all && !dmesg_restrict() {
        return Ok(());
    }

    let thread = current_thread!();
    let posix_thread = thread.as_posix_thread().unwrap();
    let init_user_ns = UserNamespace::get_init_singleton().as_ref();
    lsm_hooks::on_capable(lsm_hooks::CapableContext::new(
        init_user_ns,
        posix_thread,
        CapSet::SYSLOG,
    ))
    .or_else(|_| {
        lsm_hooks::on_capable(lsm_hooks::CapableContext::new(
            init_user_ns,
            posix_thread,
            CapSet::SYS_ADMIN,
        ))
    })
}
