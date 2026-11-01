// SPDX-License-Identifier: MPL-2.0

use aster_time::adjust::{self, Reply, Request};
use ostd::mm::VmIo;
use ostd_pod::Pod;

use super::SyscallReturn;
use crate::{
    prelude::*,
    process::{UserNamespace, credentials::capabilities::CapSet, posix_thread::AsPosixThread},
    security::lsm::hooks as lsm_hooks,
    time::{clockid_t, timespec_t},
};

const CLOCK_REALTIME: clockid_t = 0;

/// The `struct timex` of the x86-64 Linux ABI.
///
/// Reference: <https://elixir.bootlin.com/linux/v6.18/source/include/uapi/linux/timex.h>.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Pod)]
struct Timex {
    modes: u32,
    _pad0: u32,
    offset: i64,
    freq: i64,
    maxerror: i64,
    esterror: i64,
    status: i32,
    _pad1: u32,
    constant: i64,
    precision: i64,
    tolerance: i64,
    time_sec: i64,
    time_subsec: i64,
    tick: i64,
    ppsfreq: i64,
    jitter: i64,
    shift: i32,
    _pad2: u32,
    stabil: i64,
    jitcnt: i64,
    calcnt: i64,
    errcnt: i64,
    stbcnt: i64,
    tai: i32,
    _reserved: [u32; 11],
}

pub(super) fn sys_clock_settime(
    clockid: clockid_t,
    timespec_addr: Vaddr,
    ctx: &Context,
) -> Result<SyscallReturn> {
    let timespec = ctx.user_space().read_val::<timespec_t>(timespec_addr)?;
    if timespec.sec < 0 || !(0..1_000_000_000).contains(&timespec.nsec) {
        return_errno_with_message!(Errno::EINVAL, "the time is not a valid time of day");
    }
    if clockid != CLOCK_REALTIME {
        return_errno_with_message!(Errno::EINVAL, "only the realtime clock can be set");
    }

    let wall = core::time::Duration::new(timespec.sec as u64, timespec.nsec as u32);
    aster_time::set_wall_time(wall, may_set_time(ctx)).map_err(adjust_error)?;
    crate::vdso::refresh_wall_clock();
    Ok(SyscallReturn::Return(0))
}

pub(super) fn sys_adjtimex(timex_addr: Vaddr, ctx: &Context) -> Result<SyscallReturn> {
    adjust_realtime(timex_addr, ctx)
}

pub(super) fn sys_clock_adjtime(
    clockid: clockid_t,
    timex_addr: Vaddr,
    ctx: &Context,
) -> Result<SyscallReturn> {
    match clockid {
        CLOCK_REALTIME => adjust_realtime(timex_addr, ctx),
        1..=11 => return_errno_with_message!(
            Errno::EOPNOTSUPP,
            "the clock does not support adjustment"
        ),
        _ => return_errno_with_message!(Errno::EINVAL, "the clock does not exist"),
    }
}

fn adjust_realtime(timex_addr: Vaddr, ctx: &Context) -> Result<SyscallReturn> {
    let mut timex = ctx.user_space().read_val::<Timex>(timex_addr)?;
    let request = Request {
        modes: timex.modes,
        frequency: timex.freq,
        max_error: timex.maxerror,
        est_error: timex.esterror,
        status: timex.status,
        constant: timex.constant,
        time_sec: timex.time_sec,
        time_subsec: timex.time_subsec,
    };

    let reply = aster_time::adjust_wall_clock(&request, may_set_time(ctx)).map_err(adjust_error)?;

    if request.modes != 0 {
        crate::vdso::refresh_wall_clock();
    }
    fill_timex(&mut timex, &reply);
    ctx.user_space().write_val(timex_addr, &timex)?;
    Ok(SyscallReturn::Return(reply.state as isize))
}

fn fill_timex(timex: &mut Timex, reply: &Reply) {
    timex.offset = 0;
    timex.freq = reply.frequency;
    timex.maxerror = reply.max_error;
    timex.esterror = reply.est_error;
    timex.status = reply.status;
    timex.constant = reply.constant;
    timex.precision = reply.precision;
    timex.tolerance = reply.tolerance;
    timex.time_sec = reply.time_sec;
    timex.time_subsec = reply.time_subsec;
    timex.tick = reply.tick;
    timex.ppsfreq = 0;
    timex.jitter = 0;
    timex.shift = 2;
    timex.stabil = 0;
    timex.jitcnt = 0;
    timex.calcnt = 0;
    timex.errcnt = 0;
    timex.stbcnt = 0;
    timex.tai = reply.tai;
}

fn may_set_time(ctx: &Context) -> bool {
    lsm_hooks::on_capable(lsm_hooks::CapableContext::new(
        UserNamespace::get_init_singleton().as_ref(),
        ctx.posix_thread,
        CapSet::SYS_TIME,
    ))
    .is_ok()
}

fn adjust_error(error: adjust::Error) -> Error {
    match error {
        adjust::Error::Permission => {
            Error::with_message(Errno::EPERM, "changing the clock needs CAP_SYS_TIME")
        }
        adjust::Error::Invalid => {
            Error::with_message(Errno::EINVAL, "the clock adjustment is not supported")
        }
    }
}
