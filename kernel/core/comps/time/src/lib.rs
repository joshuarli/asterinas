// SPDX-License-Identifier: MPL-2.0

//! The system time of Asterinas.

#![no_std]
#![deny(unsafe_code)]

extern crate alloc;

use alloc::sync::Arc;
use core::time::Duration;

pub use clocksource::{ClockSource, Instant};
use component::{ComponentInitError, init_component};
use ostd::sync::{LocalIrqDisabled, SpinLock};
use rtc::Driver;
use spin::Once;

// Set this crate's log prefix for `ostd::log`.
macro_rules! __log_prefix {
    () => {
        "time: "
    };
}

pub mod adjust;
mod clocksource;
mod rtc;
mod tsc;

pub static VDSO_DATA_HIGH_RES_UPDATE_FN: Once<fn(Instant, u64)> = Once::new();

static RTC_DRIVER: Once<Arc<dyn Driver + Send + Sync>> = Once::new();

#[init_component]
fn time_init() -> Result<(), ComponentInitError> {
    let rtc = rtc::init_rtc_driver();
    RTC_DRIVER.call_once(|| rtc);
    tsc::init();
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct SystemTime {
    pub year: u16,
    pub month: u8,
    pub day: u8,
    pub hour: u8,
    pub minute: u8,
    pub second: u8,
    pub nanos: u64,
}

#[cfg(any(target_arch = "riscv64", target_arch = "aarch64"))]
impl From<chrono::NaiveDateTime> for SystemTime {
    fn from(time: chrono::NaiveDateTime) -> Self {
        use chrono::{Datelike, Timelike};

        Self {
            year: time.year() as u16,
            month: time.month() as u8,
            day: time.day() as u8,
            hour: time.hour() as u8,
            minute: time.minute() as u8,
            second: time.second() as u8,
            nanos: time.nanosecond() as u64,
        }
    }
}

static START_TIME: Once<SystemTime> = Once::new();

/// Returns the `START_TIME`, which is the system time when calibrating.
pub fn read_start_time() -> SystemTime {
    *START_TIME.get().unwrap()
}

/// Returns the monotonic time from the TSC clocksource.
pub fn read_monotonic_time() -> Duration {
    let instant = tsc::read_instant();
    Duration::new(instant.secs(), instant.nanos())
}

/// Returns the default (TSC) clocksource.
pub fn default_clocksource() -> Arc<ClockSource> {
    tsc::CLOCK.get().unwrap().clone()
}

static WALL_CLOCK: Once<SpinLock<adjust::WallClock, LocalIrqDisabled>> = Once::new();

/// Starts the wall clock at `wall_at_monotonic_zero`, the wall time when the monotonic clock is zero.
pub fn init_wall_clock(wall_at_monotonic_zero: Duration) {
    WALL_CLOCK.call_once(|| {
        SpinLock::new(adjust::WallClock::new(wall_at_monotonic_zero.as_nanos() as i128))
    });
}

fn monotonic_ns() -> i128 {
    read_monotonic_time().as_nanos() as i128
}

/// Returns the wall time since the Unix epoch.
pub fn read_wall_time() -> Duration {
    let wall_ns = WALL_CLOCK.get().unwrap().lock().wall_ns(monotonic_ns());
    Duration::from_nanos(wall_ns.max(0) as u64)
}

/// Returns how far the wall clock is ahead of the monotonic clock at monotonic time `at`, in
/// nanoseconds, and the frequency correction in units of 2^-16 ppm.
pub fn wall_offset_and_frequency(at: Duration) -> (i128, i64) {
    let clock = WALL_CLOCK.get().unwrap().lock();
    let at_ns = at.as_nanos() as i128;
    (clock.wall_ns(at_ns) - at_ns, clock.frequency())
}

/// Sets the wall time. Fails with [`adjust::Error::Permission`] unless `privileged`.
pub fn set_wall_time(wall: Duration, privileged: bool) -> Result<(), adjust::Error> {
    WALL_CLOCK
        .get()
        .unwrap()
        .lock()
        .set(monotonic_ns(), wall.as_nanos() as i128, privileged)
}

/// Reads or changes the wall clock as `adjtimex` does.
pub fn adjust_wall_clock(
    request: &adjust::Request,
    privileged: bool,
) -> Result<adjust::Reply, adjust::Error> {
    WALL_CLOCK
        .get()
        .unwrap()
        .lock()
        .adjust(monotonic_ns(), request, privileged)
}
