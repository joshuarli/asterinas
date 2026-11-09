// SPDX-License-Identifier: MPL-2.0

//! The disciplined clocks behind `CLOCK_MONOTONIC`, `CLOCK_REALTIME`, `clock_settime` and
//! `adjtimex`.
//!
//! As on Linux, the monotonic clock is the raw clocksource time slewed by the frequency
//! correction in units of 2^-16 ppm, and the wall clock is the monotonic clock plus an offset.
//! Changing the frequency moves the base pair of raw and monotonic time, so neither clock jumps;
//! setting or stepping the wall clock moves only the offset, so the monotonic clock never jumps.
//!
//! Reference: <https://elixir.bootlin.com/linux/v6.18/source/kernel/time/ntp.c> and
//! `adjtimex(2)`. Only the modes the clock can honor are accepted; the others fail with
//! [`Error::Invalid`] rather than succeeding without effect.

use ostd::prelude::*;

pub const ADJ_FREQUENCY: u32 = 0x0002;
pub const ADJ_MAXERROR: u32 = 0x0004;
pub const ADJ_ESTERROR: u32 = 0x0008;
pub const ADJ_STATUS: u32 = 0x0010;
pub const ADJ_TIMECONST: u32 = 0x0020;
pub const ADJ_TAI: u32 = 0x0080;
pub const ADJ_SETOFFSET: u32 = 0x0100;
pub const ADJ_MICRO: u32 = 0x1000;
pub const ADJ_NANO: u32 = 0x2000;

const SUPPORTED_MODES: u32 = ADJ_FREQUENCY
    | ADJ_MAXERROR
    | ADJ_ESTERROR
    | ADJ_STATUS
    | ADJ_TIMECONST
    | ADJ_TAI
    | ADJ_SETOFFSET
    | ADJ_MICRO
    | ADJ_NANO;

pub const STA_PLL: i32 = 0x0001;
pub const STA_PPSFREQ: i32 = 0x0002;
pub const STA_PPSTIME: i32 = 0x0004;
pub const STA_FLL: i32 = 0x0008;
pub const STA_INS: i32 = 0x0010;
pub const STA_DEL: i32 = 0x0020;
pub const STA_UNSYNC: i32 = 0x0040;
pub const STA_FREQHOLD: i32 = 0x0080;
pub const STA_NANO: i32 = 0x2000;

const STA_READ_ONLY: i32 = 0xff00;
const STA_UNSUPPORTED: i32 =
    STA_PLL | STA_PPSFREQ | STA_PPSTIME | STA_FLL | STA_INS | STA_DEL | STA_FREQHOLD;

pub const TIME_OK: i32 = 0;
pub const TIME_ERROR: i32 = 5;

const NANOS_PER_SECOND: i128 = 1_000_000_000;
const FREQUENCY_SCALE: i128 = 65536 * 1_000_000;
const MAX_FREQUENCY: i64 = 500 << 16;
const MAX_ERROR_US: i64 = 16_000_000;
const ERROR_GROWTH_US_PER_SECOND: i64 = 500;
const MAX_TIME_CONSTANT: i64 = 10;
const TICK_US: i64 = 10_000;

/// A request to read or change the wall clock, as an `adjtimex` call describes it.
#[derive(Clone, Copy, Debug, Default)]
pub struct Request {
    pub modes: u32,
    pub frequency: i64,
    pub max_error: i64,
    pub est_error: i64,
    pub status: i32,
    pub constant: i64,
    pub time_sec: i64,
    pub time_subsec: i64,
}

/// The state of the wall clock after a request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Reply {
    pub frequency: i64,
    pub max_error: i64,
    pub est_error: i64,
    pub status: i32,
    pub constant: i64,
    pub precision: i64,
    pub tolerance: i64,
    pub tick: i64,
    pub tai: i32,
    pub time_sec: i64,
    pub time_subsec: i64,
    pub state: i32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// The caller may not change the clock.
    Permission,
    /// A mode, flag or value is outside what the clock supports.
    Invalid,
}

/// The monotonic and wall clocks, both disciplined by one frequency correction.
#[derive(Debug)]
pub struct WallClock {
    base_raw_ns: i128,
    base_monotonic_ns: i128,
    wall_offset_ns: i128,
    frequency: i64,
    max_error_us: i64,
    max_error_at_second: i64,
    est_error_us: i64,
    status: i32,
    constant: i64,
    tai: i32,
}

impl WallClock {
    /// Creates clocks that read zero and `wall_at_raw_zero_ns` when the raw clock is zero.
    pub const fn new(wall_at_raw_zero_ns: i128) -> Self {
        Self {
            base_raw_ns: 0,
            base_monotonic_ns: 0,
            wall_offset_ns: wall_at_raw_zero_ns,
            frequency: 0,
            max_error_us: MAX_ERROR_US,
            max_error_at_second: 0,
            est_error_us: MAX_ERROR_US,
            status: STA_UNSYNC,
            constant: 2,
            tai: 0,
        }
    }

    /// Returns the slewed monotonic time in nanoseconds at raw clocksource time `raw_ns`.
    pub fn monotonic_ns(&self, raw_ns: i128) -> i128 {
        let elapsed = raw_ns - self.base_raw_ns;
        self.base_monotonic_ns + elapsed + elapsed * i128::from(self.frequency) / FREQUENCY_SCALE
    }

    /// Returns the wall time in nanoseconds since the Unix epoch at raw clocksource time `raw_ns`.
    pub fn wall_ns(&self, raw_ns: i128) -> i128 {
        self.monotonic_ns(raw_ns) + self.wall_offset_ns
    }

    /// Returns the current frequency correction in units of 2^-16 ppm.
    pub fn frequency(&self) -> i64 {
        self.frequency
    }

    /// Sets the wall time, as `clock_settime(CLOCK_REALTIME)` does.
    pub fn set(
        &mut self,
        raw_ns: i128,
        wall_ns: i128,
        privileged: bool,
    ) -> Result<(), Error> {
        if !privileged {
            return Err(Error::Permission);
        }
        if wall_ns < 0 {
            return Err(Error::Invalid);
        }
        self.wall_offset_ns = wall_ns - self.monotonic_ns(raw_ns);
        Ok(())
    }

    /// Reads or changes the clock, as `adjtimex` does.
    pub fn adjust(
        &mut self,
        raw_ns: i128,
        request: &Request,
        privileged: bool,
    ) -> Result<Reply, Error> {
        let modes = request.modes;
        if modes != 0 && !privileged {
            return Err(Error::Permission);
        }
        if modes & !SUPPORTED_MODES != 0 {
            return Err(Error::Invalid);
        }
        if modes & ADJ_STATUS != 0 && request.status & STA_UNSUPPORTED != 0 {
            return Err(Error::Invalid);
        }
        if modes & ADJ_TAI != 0 && (request.constant < 0 || request.constant > i64::from(i32::MAX)) {
            return Err(Error::Invalid);
        }
        let step_ns = if modes & ADJ_SETOFFSET != 0 {
            let limit = if modes & ADJ_NANO != 0 {
                NANOS_PER_SECOND
            } else {
                NANOS_PER_SECOND / 1000
            };
            if request.time_subsec < 0 || i128::from(request.time_subsec) >= limit {
                return Err(Error::Invalid);
            }
            let subsec_ns = if modes & ADJ_NANO != 0 {
                i128::from(request.time_subsec)
            } else {
                i128::from(request.time_subsec) * 1000
            };
            let step = i128::from(request.time_sec) * NANOS_PER_SECOND + subsec_ns;
            if self.wall_ns(raw_ns) + step < 0 {
                return Err(Error::Invalid);
            }
            Some(step)
        } else {
            None
        };

        self.refresh_error(raw_ns);
        if modes & ADJ_FREQUENCY != 0 {
            self.rebase(raw_ns);
            self.frequency = request.frequency.clamp(-MAX_FREQUENCY, MAX_FREQUENCY);
        }
        if let Some(step) = step_ns {
            self.wall_offset_ns += step;
        }
        if modes & ADJ_MAXERROR != 0 {
            self.max_error_us = request.max_error.clamp(0, MAX_ERROR_US);
            self.max_error_at_second = raw_seconds(raw_ns);
        }
        if modes & ADJ_ESTERROR != 0 {
            self.est_error_us = request.est_error.clamp(0, MAX_ERROR_US);
        }
        if modes & ADJ_STATUS != 0 {
            self.status = (self.status & STA_READ_ONLY) | (request.status & !STA_READ_ONLY);
        }
        if modes & ADJ_TIMECONST != 0 {
            self.constant = request.constant.clamp(0, MAX_TIME_CONSTANT);
        }
        if modes & ADJ_TAI != 0 {
            self.tai = request.constant as i32;
        }
        if modes & ADJ_NANO != 0 {
            self.status |= STA_NANO;
        } else if modes & ADJ_MICRO != 0 {
            self.status &= !STA_NANO;
        }

        self.refresh_error(raw_ns);
        let wall_ns = self.wall_ns(raw_ns);
        let time_sec = wall_ns.div_euclid(NANOS_PER_SECOND) as i64;
        let sub_ns = wall_ns.rem_euclid(NANOS_PER_SECOND) as i64;
        Ok(Reply {
            frequency: self.frequency,
            max_error: self.max_error_us,
            est_error: self.est_error_us,
            status: self.status,
            constant: self.constant,
            precision: 1,
            tolerance: MAX_FREQUENCY,
            tick: TICK_US,
            tai: self.tai,
            time_sec,
            time_subsec: if self.status & STA_NANO != 0 {
                sub_ns
            } else {
                sub_ns / 1000
            },
            state: if self.status & STA_UNSYNC != 0 {
                TIME_ERROR
            } else {
                TIME_OK
            },
        })
    }

    fn rebase(&mut self, raw_ns: i128) {
        self.base_monotonic_ns = self.monotonic_ns(raw_ns);
        self.base_raw_ns = raw_ns;
    }

    fn refresh_error(&mut self, raw_ns: i128) {
        let now = raw_seconds(raw_ns);
        let grown = self.max_error_us + (now - self.max_error_at_second) * ERROR_GROWTH_US_PER_SECOND;
        self.max_error_at_second = now;
        if grown > MAX_ERROR_US {
            self.max_error_us = MAX_ERROR_US;
            self.status |= STA_UNSYNC;
        } else {
            self.max_error_us = grown;
        }
    }
}

fn raw_seconds(raw_ns: i128) -> i64 {
    (raw_ns / NANOS_PER_SECOND) as i64
}

#[cfg(ktest)]
mod test {
    use super::*;

    const SECOND: i128 = NANOS_PER_SECOND;
    const START: i128 = 1_700_000_000 * SECOND;

    fn adjust(clock: &mut WallClock, now: i128, request: Request) -> Result<Reply, Error> {
        clock.adjust(now, &request, true)
    }

    #[ktest]
    fn a_new_clock_follows_the_monotonic_clock_and_reports_unsynchronized() {
        let mut clock = WallClock::new(START);
        assert_eq!(clock.wall_ns(5 * SECOND), START + 5 * SECOND);
        let reply = adjust(&mut clock, 5 * SECOND, Request::default()).unwrap();
        assert_eq!(reply.state, TIME_ERROR);
        assert_ne!(reply.status & STA_UNSYNC, 0);
        assert_eq!(reply.frequency, 0);
        assert_eq!(reply.tick, 10_000);
    }

    #[ktest]
    fn setting_the_clock_moves_it_by_exactly_the_difference() {
        let mut clock = WallClock::new(START);
        clock.set(10 * SECOND, START + 100 * SECOND, true).unwrap();
        assert_eq!(clock.wall_ns(10 * SECOND), START + 100 * SECOND);
        assert_eq!(clock.wall_ns(12 * SECOND), START + 102 * SECOND);
        assert_eq!(clock.set(10 * SECOND, -1, true), Err(Error::Invalid));
        assert_eq!(clock.set(10 * SECOND, 0, false), Err(Error::Permission));
    }

    #[ktest]
    fn a_positive_and_a_negative_step_apply_in_nanoseconds_or_microseconds() {
        let mut clock = WallClock::new(START);
        let step = |sec, subsec, nano| Request {
            modes: ADJ_SETOFFSET | if nano { ADJ_NANO } else { 0 },
            time_sec: sec,
            time_subsec: subsec,
            ..Request::default()
        };
        adjust(&mut clock, SECOND, step(2, 500_000_000, true)).unwrap();
        assert_eq!(clock.wall_ns(SECOND), START + SECOND + 2 * SECOND + 500_000_000);
        adjust(&mut clock, SECOND, step(-3, 250_000, false)).unwrap();
        assert_eq!(
            clock.wall_ns(SECOND),
            START + SECOND + 2 * SECOND + 500_000_000 - 3 * SECOND + 250_000_000
        );
        assert_eq!(adjust(&mut clock, SECOND, step(0, 1_000_000_000, true)), Err(Error::Invalid));
        assert_eq!(adjust(&mut clock, SECOND, step(0, 1_000_000, false)), Err(Error::Invalid));
        assert_eq!(adjust(&mut clock, SECOND, step(0, -1, true)), Err(Error::Invalid));
        assert_eq!(adjust(&mut clock, SECOND, step(-2_000_000_000, 0, true)), Err(Error::Invalid));
    }

    #[ktest]
    fn a_frequency_correction_scales_elapsed_time_and_reads_back() {
        let mut clock = WallClock::new(START);
        let reply = adjust(
            &mut clock,
            100 * SECOND,
            Request { modes: ADJ_FREQUENCY, frequency: 100 << 16, ..Request::default() },
        )
        .unwrap();
        assert_eq!(reply.frequency, 100 << 16);
        assert_eq!(clock.wall_ns(100 * SECOND), START + 100 * SECOND);
        assert_eq!(clock.wall_ns(200 * SECOND), START + 200 * SECOND + 10_000 * 1000);
        adjust(
            &mut clock,
            200 * SECOND,
            Request { modes: ADJ_FREQUENCY, frequency: -(50 << 16), ..Request::default() },
        )
        .unwrap();
        assert_eq!(clock.wall_ns(300 * SECOND), START + 300 * SECOND + 10_000 * 1000 - 5_000 * 1000);
    }

    #[ktest]
    fn a_frequency_correction_slews_the_monotonic_clock_without_a_jump() {
        let mut clock = WallClock::new(START);
        assert_eq!(clock.monotonic_ns(100 * SECOND), 100 * SECOND);
        adjust(
            &mut clock,
            100 * SECOND,
            Request { modes: ADJ_FREQUENCY, frequency: 100 << 16, ..Request::default() },
        )
        .unwrap();
        assert_eq!(clock.monotonic_ns(100 * SECOND), 100 * SECOND);
        assert_eq!(clock.monotonic_ns(200 * SECOND), 200 * SECOND + 10_000 * 1000);
        adjust(
            &mut clock,
            200 * SECOND,
            Request { modes: ADJ_FREQUENCY, frequency: -(50 << 16), ..Request::default() },
        )
        .unwrap();
        assert_eq!(clock.monotonic_ns(200 * SECOND), 200 * SECOND + 10_000 * 1000);
        assert_eq!(
            clock.monotonic_ns(300 * SECOND),
            300 * SECOND + 10_000 * 1000 - 5_000 * 1000
        );
        assert_eq!(clock.wall_ns(300 * SECOND) - clock.monotonic_ns(300 * SECOND), START);
    }

    #[ktest]
    fn setting_or_stepping_the_wall_clock_leaves_the_monotonic_clock_alone() {
        let mut clock = WallClock::new(START);
        adjust(
            &mut clock,
            10 * SECOND,
            Request { modes: ADJ_FREQUENCY, frequency: 200 << 16, ..Request::default() },
        )
        .unwrap();
        let before = clock.monotonic_ns(20 * SECOND);
        clock.set(20 * SECOND, START + 1_000 * SECOND, true).unwrap();
        adjust(
            &mut clock,
            20 * SECOND,
            Request { modes: ADJ_SETOFFSET | ADJ_NANO, time_sec: -7, ..Request::default() },
        )
        .unwrap();
        assert_eq!(clock.monotonic_ns(20 * SECOND), before);
        assert_eq!(clock.wall_ns(20 * SECOND), START + 993 * SECOND);
        assert_eq!(
            clock.monotonic_ns(30 * SECOND) - before,
            clock.wall_ns(30 * SECOND) - clock.wall_ns(20 * SECOND)
        );
    }

    #[ktest]
    fn the_frequency_is_clamped_to_five_hundred_ppm() {
        let mut clock = WallClock::new(START);
        let reply = adjust(
            &mut clock,
            0,
            Request { modes: ADJ_FREQUENCY, frequency: 1_000 << 16, ..Request::default() },
        )
        .unwrap();
        assert_eq!(reply.frequency, 500 << 16);
        let reply = adjust(
            &mut clock,
            0,
            Request { modes: ADJ_FREQUENCY, frequency: -(1_000 << 16), ..Request::default() },
        )
        .unwrap();
        assert_eq!(reply.frequency, -(500 << 16));
    }

    #[ktest]
    fn changing_the_status_keeps_the_read_only_bits_and_clears_unsync() {
        let mut clock = WallClock::new(START);
        adjust(&mut clock, 0, Request { modes: ADJ_NANO, ..Request::default() }).unwrap();
        let reply =
            adjust(&mut clock, 0, Request { modes: ADJ_STATUS, status: 0, ..Request::default() }).unwrap();
        assert_eq!(reply.status, STA_NANO);
        assert_eq!(reply.state, TIME_OK);
        let reply = adjust(
            &mut clock,
            0,
            Request { modes: ADJ_STATUS, status: STA_UNSYNC | STA_NANO, ..Request::default() },
        )
        .unwrap();
        assert_eq!(reply.status, STA_UNSYNC | STA_NANO);
        assert_eq!(reply.state, TIME_ERROR);
    }

    #[ktest]
    fn unsupported_modes_and_status_bits_are_rejected() {
        let mut clock = WallClock::new(START);
        for modes in [0x0001, 0x4000, 0x8001, 0x0040] {
            assert_eq!(
                adjust(&mut clock, 0, Request { modes, ..Request::default() }),
                Err(Error::Invalid),
                "mode {modes:#x}"
            );
        }
        for status in [STA_PLL, STA_FLL, STA_INS, STA_DEL, STA_FREQHOLD, STA_PPSTIME] {
            assert_eq!(
                adjust(&mut clock, 0, Request { modes: ADJ_STATUS, status, ..Request::default() }),
                Err(Error::Invalid),
                "status {status:#x}"
            );
        }
    }

    #[ktest]
    fn only_a_privileged_caller_may_change_the_clock() {
        let mut clock = WallClock::new(START);
        assert!(clock.adjust(0, &Request::default(), false).is_ok());
        assert_eq!(
            clock.adjust(0, &Request { modes: ADJ_FREQUENCY, ..Request::default() }, false),
            Err(Error::Permission)
        );
        assert_eq!(clock.frequency(), 0);
    }

    #[ktest]
    fn a_rejected_request_changes_nothing() {
        let mut clock = WallClock::new(START);
        let request = Request {
            modes: ADJ_FREQUENCY | ADJ_SETOFFSET | ADJ_NANO,
            frequency: 10 << 16,
            time_sec: 1,
            time_subsec: 2_000_000_000,
            ..Request::default()
        };
        assert_eq!(adjust(&mut clock, SECOND, request), Err(Error::Invalid));
        assert_eq!(clock.frequency(), 0);
        assert_eq!(clock.wall_ns(SECOND), START + SECOND);
    }

    #[ktest]
    fn the_maximum_error_grows_by_five_hundred_microseconds_per_second() {
        let mut clock = WallClock::new(START);
        adjust(
            &mut clock,
            10 * SECOND,
            Request { modes: ADJ_MAXERROR | ADJ_ESTERROR, max_error: 1_000, est_error: 40, ..Request::default() },
        )
        .unwrap();
        let reply = adjust(&mut clock, 14 * SECOND, Request::default()).unwrap();
        assert_eq!(reply.max_error, 1_000 + 4 * 500);
        assert_eq!(reply.est_error, 40);
        let reply = adjust(
            &mut clock,
            14 * SECOND,
            Request { modes: ADJ_STATUS, status: 0, ..Request::default() },
        )
        .unwrap();
        assert_eq!(reply.state, TIME_OK);
        let reply = adjust(&mut clock, 100_000 * SECOND, Request::default()).unwrap();
        assert_eq!(reply.max_error, 16_000_000);
        assert_eq!(reply.state, TIME_ERROR);
    }
}
