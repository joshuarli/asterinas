// SPDX-License-Identifier: MPL-2.0

use core::{
    fmt::Display,
    sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering},
    time::Duration,
};

use atomic_integer_wrapper::define_atomic_version_of_integer_like_type;
use alloc::sync::Weak;
use ostd::sync::SpinLock;

use crate::{
    events::IoEvents,
    fs::{
        file::{AccessMode, CreationFlags, FileCommon, FileLike, StatusFlags, file_table::FdFlags},
        pseudofs::AnonInodeFs,
    },
    prelude::*,
    process::signal::{PollHandle, Pollable, Pollee},
    syscall::{ClockId, create_timer_for_clock},
    time::{
        Timer, clockid_t,
        timer::{Timeout, TimerGuard},
    },
};

/// A file-like object representing a timer that can be used with file descriptors.
pub(crate) struct TimerfdFile {
    clockid: clockid_t,
    timer: Arc<Timer>,
    ticks: Arc<AtomicU64>,
    pollee: Pollee,
    settime_flags: AtomicTFDSetTimeFlags,
    common: FileCommon,
    cancellation: Arc<TimerfdCancellation>,
}

struct TimerfdCancellation {
    armed: AtomicBool,
    cancelled: AtomicBool,
    pollee: Pollee,
}

static CLOCK_STEPS: SpinLock<Vec<Weak<TimerfdCancellation>>> = SpinLock::new(Vec::new());

pub(crate) fn clock_step<F, T>(change: F) -> Result<T>
where
    F: FnOnce() -> Result<T>,
{
    let mut timers = CLOCK_STEPS.disable_irq().lock();
    let result = change()?;
    timers.retain(|entry| {
        if let Some(timer) = entry.upgrade() {
            if timer.armed.load(Ordering::Relaxed) {
                timer.cancelled.store(true, Ordering::Release);
                timer.pollee.notify(IoEvents::IN);
            }
            true
        } else {
            false
        }
    });
    drop(timers);
    crate::time::clocks::RealTimeClock::timer_manager().process_expired_timers();
    crate::time::clocks::TaiClock::timer_manager().process_expired_timers();
    Ok(result)
}

pub(crate) fn with_clock_step_lock<F: FnOnce()>(f: F) {
    let _guard = CLOCK_STEPS.disable_irq().lock();
    f();
}

bitflags! {
    /// The flags used for timerfd-related operations.
    pub(crate) struct TFDFlags: u32 {
        const TFD_CLOEXEC = CreationFlags::O_CLOEXEC.bits();
        const TFD_NONBLOCK = StatusFlags::O_NONBLOCK.bits();
    }
}

// Required by `define_atomic_version_of_integer_like_type`.
impl TryFrom<u32> for TFDFlags {
    type Error = Error;

    fn try_from(value: u32) -> Result<Self> {
        Self::from_bits(value).ok_or_else(|| Error::with_message(Errno::EINVAL, "invalid TFDFlags"))
    }
}

// Required by `define_atomic_version_of_integer_like_type`.
impl From<TFDFlags> for u32 {
    fn from(value: TFDFlags) -> Self {
        value.bits()
    }
}

bitflags! {
    /// The flags used for timerfd settime operations.
    pub(crate) struct TFDSetTimeFlags: u32 {
        const TFD_TIMER_ABSTIME = 0x1;
        const TFD_TIMER_CANCEL_ON_SET = 0x2;
    }
}

// Required by `define_atomic_version_of_integer_like_type`.
impl TryFrom<u32> for TFDSetTimeFlags {
    type Error = Error;

    fn try_from(value: u32) -> Result<Self> {
        Self::from_bits(value)
            .ok_or_else(|| Error::with_message(Errno::EINVAL, "invalid TFDSetTimeFlags"))
    }
}

// Required by `define_atomic_version_of_integer_like_type`.
impl From<TFDSetTimeFlags> for u32 {
    fn from(value: TFDSetTimeFlags) -> Self {
        value.bits()
    }
}

define_atomic_version_of_integer_like_type!(TFDSetTimeFlags, try_from = true, {
    /// An atomic version of `TFDSetTimeFlags`.
    #[derive(Debug, Default)]
    struct AtomicTFDSetTimeFlags(AtomicU32);
});

impl TimerfdFile {
    /// Creates a new `TimerfdFile` instance.
    pub(crate) fn new(clock_id: ClockId, flags: TFDFlags, ctx: &Context) -> Result<Self> {
        let is_valid = matches!(
            clock_id,
            ClockId::CLOCK_REALTIME | ClockId::CLOCK_MONOTONIC | ClockId::CLOCK_BOOTTIME
        );
        if !is_valid {
            return_errno_with_message!(Errno::EINVAL, "invalid clock ID");
        }

        let ticks = Arc::new(AtomicU64::new(0));
        let pollee = Pollee::new();

        let timer = {
            let ticks = ticks.clone();
            let pollee = pollee.clone();

            let expired_fn = move |_guard: TimerGuard| {
                ticks.fetch_add(1, Ordering::Relaxed);
                pollee.notify(IoEvents::IN);
            };
            create_timer_for_clock(clock_id, expired_fn, ctx)
        }?;

        let pseudo_path = AnonInodeFs::new_path(|_| "anon_inode:[timerfd]".to_string());
        let status_flags = if flags.contains(TFDFlags::TFD_NONBLOCK) {
            StatusFlags::O_NONBLOCK
        } else {
            StatusFlags::empty()
        };

        let cancellation = Arc::new(TimerfdCancellation {
            armed: AtomicBool::new(false),
            cancelled: AtomicBool::new(false),
            pollee: pollee.clone(),
        });
        Ok(TimerfdFile {
            clockid: clock_id as clockid_t,
            cancellation,
            timer,
            ticks,
            pollee,
            settime_flags: AtomicTFDSetTimeFlags::default(),
            // Reference: <https://elixir.bootlin.com/linux/v7.0/source/fs/timerfd.c#L436>.
            common: FileCommon::new(pseudo_path, AccessMode::O_RDWR, status_flags),
        })
    }

    // Sets the timer's timeout and interval.
    //
    // The remaining time and old interval are saved before the settings are applied, and then
    // returned afterwards.
    pub(crate) fn set_time(
        &self,
        expire_time: Duration,
        interval: Duration,
        flags: TFDSetTimeFlags,
    ) -> (Duration, Duration) {
        let mut registrations = CLOCK_STEPS.disable_irq().lock();
        let mut timer_guard = self.timer.lock();
        let cancel_on_set = self.clockid == ClockId::CLOCK_REALTIME as clockid_t
            && flags.contains(TFDSetTimeFlags::TFD_TIMER_ABSTIME | TFDSetTimeFlags::TFD_TIMER_CANCEL_ON_SET);
        self.cancellation.armed.store(cancel_on_set && expire_time != Duration::ZERO, Ordering::Relaxed);
        self.cancellation.cancelled.store(false, Ordering::Release);
        registrations.retain(|entry| entry.strong_count() != 0 && !entry.ptr_eq(&Arc::downgrade(&self.cancellation)));
        if cancel_on_set && expire_time != Duration::ZERO {
            registrations.push(Arc::downgrade(&self.cancellation));
        }

        let (old_interval, remain) = (timer_guard.interval(), timer_guard.remain());

        timer_guard.set_interval(interval);

        // Cancel the timer and clear the ticks counter.
        timer_guard.cancel();
        self.ticks.store(0, Ordering::Relaxed);

        if expire_time != Duration::ZERO {
            let timeout = if flags.contains(TFDSetTimeFlags::TFD_TIMER_ABSTIME) {
                Timeout::When(expire_time)
            } else {
                Timeout::After(expire_time)
            };

            timer_guard.set_timeout(timeout);
            self.settime_flags.store(flags, Ordering::Relaxed);
        }

        (old_interval, remain)
    }

    /// Gets the timer's remaining time and interval.
    pub(crate) fn get_time(&self) -> (Duration, Duration) {
        let timer_guard = self.timer.lock();
        (timer_guard.interval(), timer_guard.remain())
    }

    fn is_nonblocking(&self) -> bool {
        self.common.is_nonblocking()
    }

    fn try_read(&self, writer: &mut VmWriter) -> Result<()> {
        if self.cancellation.cancelled.swap(false, Ordering::AcqRel) {
            self.ticks.store(0, Ordering::Relaxed);
            return_errno_with_message!(Errno::ECANCELED, "realtime clock was set");
        }
        let ticks = self.ticks.fetch_and(0, Ordering::Relaxed);

        if ticks == 0 {
            return_errno_with_message!(Errno::EAGAIN, "the counter is zero");
        }

        writer.write_fallible(&mut ticks.as_bytes().into())?;

        Ok(())
    }

    fn check_io_events(&self) -> IoEvents {
        let mut events = IoEvents::empty();

        if self.cancellation.cancelled.load(Ordering::Acquire) || self.ticks.load(Ordering::Relaxed) != 0 {
            events |= IoEvents::IN;
        }

        events
    }
}

impl Pollable for TimerfdFile {
    fn poll(&self, mask: IoEvents, poller: Option<&mut PollHandle>) -> IoEvents {
        self.pollee
            .poll_with(mask, poller, || self.check_io_events())
    }
}

impl FileLike for TimerfdFile {
    fn read(&self, writer: &mut VmWriter) -> Result<usize> {
        let read_len = size_of::<u64>();

        if writer.avail() < read_len {
            return_errno_with_message!(Errno::EINVAL, "buf len is less len u64 size");
        }

        if self.is_nonblocking() {
            self.try_read(writer)?;
        } else {
            self.wait_events(IoEvents::IN, None, || self.try_read(writer))?;
        }

        Ok(read_len)
    }

    fn common(&self) -> &FileCommon {
        &self.common
    }

    fn dump_proc_fdinfo(self: Arc<Self>, fd_flags: FdFlags) -> Box<dyn Display> {
        struct FdInfo {
            flags: u32,
            clockid: i32,
            ticks: u64,
            settime_flags: u32,
            it_value: Duration,
            it_interval: Duration,
        }

        impl Display for FdInfo {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                writeln!(f, "pos:\t{}", 0)?;
                writeln!(f, "flags:\t0{:o}", self.flags)?;
                writeln!(f, "mnt_id:\t{}", AnonInodeFs::mount_node().id())?;
                writeln!(f, "ino:\t{}", AnonInodeFs::shared_inode().ino())?;
                writeln!(f, "clockid: {}", self.clockid)?;
                writeln!(f, "ticks: {}", self.ticks)?;
                writeln!(f, "settime flags: 0{:o}", self.settime_flags)?;
                writeln!(
                    f,
                    "it_value: ({}, {})",
                    self.it_value.as_secs(),
                    self.it_value.subsec_nanos()
                )?;
                writeln!(
                    f,
                    "it_interval: ({}, {})",
                    self.it_interval.as_secs(),
                    self.it_interval.subsec_nanos()
                )
            }
        }

        let mut flags = self.common.status_flags().bits() | self.common.access_mode() as u32;
        if fd_flags.contains(FdFlags::CLOEXEC) {
            flags |= CreationFlags::O_CLOEXEC.bits();
        }

        let timer_guard = self.timer.lock();
        Box::new(FdInfo {
            flags,
            clockid: self.clockid,
            ticks: self.ticks.load(Ordering::Relaxed),
            settime_flags: self.settime_flags.load(Ordering::Relaxed).bits(),
            it_value: timer_guard.expired_time(),
            it_interval: timer_guard.interval(),
        })
    }
}
