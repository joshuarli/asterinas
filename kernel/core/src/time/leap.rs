// SPDX-License-Identifier: MPL-2.0

use core::time::Duration;

use alloc::sync::Arc;
use ostd::sync::{LocalIrqDisabled, SpinLock};

use crate::{
    prelude::*,
    time::{
        clocks::RealTimeClock,
        timer::{Timeout, Timer},
    },
};

struct LeapTimer {
    deadline_ns: i64,
    timer: Option<Arc<Timer>>,
}

static LEAP_TIMER: SpinLock<LeapTimer, LocalIrqDisabled> =
    SpinLock::new(LeapTimer { deadline_ns: 0, timer: None });

/// Arms the wall-clock timer that applies a scheduled leap second at `deadline_ns`.
///
/// A zero deadline disarms it. Linux applies the leap from `second_overflow`, driven by the
/// wall clock; keying the timer to the wall clock gives the same behaviour across a clock step.
pub(crate) fn set_deadline(deadline_ns: i64) {
    let mut leap = LEAP_TIMER.lock();
    if leap.deadline_ns == deadline_ns {
        return;
    }
    leap.deadline_ns = deadline_ns;
    if let Some(timer) = leap.timer.take() {
        timer.lock().cancel();
    }
    if deadline_ns > 0 {
        let timer = RealTimeClock::timer_manager().create_timer(|_guard| {
            if aster_time::apply_pending_leap() {
                crate::vdso::refresh_wall_clock();
            }
        });
        timer
            .lock()
            .set_timeout(Timeout::When(Duration::from_nanos(deadline_ns as u64)));
        leap.timer = Some(timer);
    }
}
