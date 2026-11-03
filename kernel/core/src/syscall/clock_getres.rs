// SPDX-License-Identifier: MPL-2.0

use core::time::Duration;

use ostd::{mm::VmIo, timer::TIMER_FREQ};

use super::{
    SyscallReturn,
    clock_gettime::{ClockId, read_clock},
};
use crate::{prelude::*, time::{clockid_t, timespec_t}};

pub(super) fn sys_clock_getres(
    clockid: clockid_t,
    timespec_addr: Vaddr,
    ctx: &Context,
) -> Result<SyscallReturn> {
    debug!("clockid = {:?}", clockid);

    let resolution = clock_resolution(clockid, ctx)?;

    if timespec_addr != 0 {
        let timespec = timespec_t::from(resolution);
        ctx.user_space().write_val(timespec_addr, &timespec)?;
    }

    Ok(SyscallReturn::Return(0))
}

fn clock_resolution(clockid: clockid_t, ctx: &Context) -> Result<Duration> {
    read_clock(clockid, ctx)?;

    Ok(match ClockId::try_from(clockid) {
        Ok(ClockId::CLOCK_REALTIME_COARSE | ClockId::CLOCK_MONOTONIC_COARSE) => {
            Duration::from_nanos(1_000_000_000 / TIMER_FREQ)
        }
        _ => Duration::from_nanos(1),
    })
}
