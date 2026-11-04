// SPDX-License-Identifier: MPL-2.0

use core::sync::atomic::{AtomicU64, Ordering};
use crate::{prelude::*, process::posix_thread::AsPosixThread};

static PING_GROUP_RANGE: AtomicU64 = AtomicU64::new(1u64 << 32);

pub(crate) fn ping_group_range() -> (u32, u32) {
    let range = PING_GROUP_RANGE.load(Ordering::Relaxed);
    ((range >> 32) as u32, range as u32)
}

pub(crate) fn set_ping_group_range(low: u32, high: u32) {
    let (low, high) = if low > high { (1, 0) } else { (low, high) };
    PING_GROUP_RANGE.store((u64::from(low) << 32) | u64::from(high), Ordering::Relaxed);
}

pub(super) fn check_ping_group() -> Result<()> {
    let credentials = current_thread!().as_posix_thread().unwrap().credentials();
    let (low, high) = ping_group_range();
    let contains = |gid: u32| low <= gid && gid <= high;
    if contains(credentials.egid().into()) || credentials.groups().iter().any(|gid| contains((*gid).into())) {
        Ok(())
    } else {
        return_errno_with_message!(Errno::EACCES, "the process group is not permitted to create ping sockets");
    }
}
