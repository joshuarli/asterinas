// SPDX-License-Identifier: MPL-2.0

use ostd::{mm::VmIo, sync::SpinLock};

use super::{SyscallReturn, clock_adjust::{adjust_error, may_set_time}};
use crate::{
    prelude::*,
    time::{SystemTime, timeval_t, timezone_t},
};

static TIMEZONE: SpinLock<(timezone_t, bool)> = SpinLock::new((timezone_t { tz_minuteswest: 0, tz_dsttime: 0 }, true));

pub(super) fn sys_gettimeofday(
    timeval_addr: Vaddr,
    timezone_addr: Vaddr,
    ctx: &Context,
) -> Result<SyscallReturn> {
    if timeval_addr != 0 {
        let time_val = {
            let now = SystemTime::now();
            let time_duration = now.duration_since(&SystemTime::UNIX_EPOCH)?;
            timeval_t::from(time_duration)
        };
        ctx.user_space().write_val(timeval_addr, &time_val)?;
    }

    if timezone_addr != 0 {
        let tz = TIMEZONE.lock().0;
        ctx.user_space().write_val(timezone_addr, &tz)?;
    }

    Ok(SyscallReturn::Return(0))
}

pub(super) fn sys_settimeofday(
    timeval_addr: Vaddr,
    timezone_addr: Vaddr,
    ctx: &Context,
) -> Result<SyscallReturn> {
    let wall = if timeval_addr != 0 {
        Some(core::time::Duration::try_from(ctx.user_space().read_val::<timeval_t>(timeval_addr)?)?)
    } else {
        None
    };
    let timezone = if timezone_addr != 0 {
        let tz = ctx.user_space().read_val::<timezone_t>(timezone_addr)?;
        if !(-900..=900).contains(&tz.tz_minuteswest) {
            return_errno_with_message!(Errno::EINVAL, "invalid timezone");
        }
        Some(tz)
    } else {
        None
    };
    if !may_set_time(ctx) {
        return_errno_with_message!(Errno::EPERM, "changing the clock needs CAP_SYS_TIME");
    }
    if let Some(tz) = timezone {
        let mut state = TIMEZONE.lock();
        let warp = state.1 && wall.is_none();
        *state = (tz, false);
        crate::vdso::set_timezone(tz.tz_minuteswest, tz.tz_dsttime);
        if warp {
            let now = aster_time::read_wall_time();
            let delta = i64::from(tz.tz_minuteswest) * 60;
            let warped = if delta >= 0 {
                now.saturating_add(core::time::Duration::from_secs(delta as u64))
            } else {
                now.saturating_sub(core::time::Duration::from_secs((-delta) as u64))
            };
            crate::time::timerfd::clock_step(|| {
                aster_time::set_wall_time(warped, true).map_err(adjust_error)?;
                crate::vdso::refresh_wall_clock();
                Ok(())
            })?;
        }
    }
    if let Some(wall) = wall {
        crate::time::timerfd::clock_step(|| {
            aster_time::set_wall_time(wall, true).map_err(adjust_error)?;
            crate::vdso::refresh_wall_clock();
            Ok(())
        })?;
    }
    Ok(SyscallReturn::Return(0))
}
