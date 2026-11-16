// SPDX-License-Identifier: MPL-2.0

use alloc::{
    boxed::Box,
    collections::BTreeMap,
    sync::{Arc, Weak},
    vec::Vec,
};
use core::{
    sync::atomic::{AtomicBool, Ordering},
    time::Duration,
};

use ostd::sync::{LocalIrqDisabled, SpinLock, SpinLockGuard};

use super::Clock;

/// A timeout, represented in one of the two ways.
#[derive(Clone, Debug)]
pub(crate) enum Timeout {
    /// The timeout is reached _after_ the `Duration` time is elapsed.
    After(Duration),
    /// The timeout is reached _when_ the clock's time is equal to `Duration`.
    When(Duration),
}

/// A timer with periodic functionality.
///
/// Setting the timer will trigger a callback function upon expiration of
/// the set time. To enable its periodic functionality, users should set
/// its `interval` field with [`TimerGuard::set_interval`]. By doing this,
/// the timer will use the interval time to configure a new timing after expiration.
pub(crate) struct Timer {
    inner: SpinLock<TimerInner>,
    timer_manager: Arc<TimerManager>,
    registered_callback: Box<dyn Fn(TimerGuard) + Send + Sync>,
}

#[derive(Default)]
struct TimerInner {
    interval: Duration,
    timer_callback: Weak<TimerCallback>,
}

/// A guard that provides exclusive access to a `Timer`.
pub(crate) struct TimerGuard<'a> {
    inner: SpinLockGuard<'a, TimerInner, LocalIrqDisabled>,
    timer: &'a Arc<Timer>,
}

impl TimerGuard<'_> {
    /// Sets the interval time for this timer.
    ///
    /// The timer will be reset with the interval time upon expiration.
    pub(crate) fn set_interval(&mut self, interval: Duration) {
        self.inner.interval = interval;
    }

    /// Sets the timer with a timeout.
    ///
    /// The registered callback function of this timer will be invoked
    /// when reaching timeout. If the timer has a valid interval, this timer
    /// will be set again with the interval when reaching timeout.
    pub(crate) fn set_timeout(&mut self, timeout: Timeout) {
        let (expired_time, relative_clock) = match timeout {
            Timeout::After(timeout) => {
                let clock = self.timer.timer_manager.relative_clock.as_ref();
                let now = clock.unwrap_or(&self.timer.timer_manager.clock).read_time();
                (now + timeout, clock.is_some())
            }
            Timeout::When(timeout) => (timeout, false),
        };

        let timer_weak = Arc::downgrade(self.timer);
        let new_timer_callback = Arc::new(TimerCallback::new(expired_time, timer_weak, relative_clock));

        if let Some(timer_callback) = self.inner.timer_callback.upgrade() {
            self.timer.timer_manager.cancel(&timer_callback);
        }

        self.inner.timer_callback = Arc::downgrade(&new_timer_callback);
        self.timer.timer_manager.insert(new_timer_callback);
    }

    /// Cancels the currently set `TimerCallback`.
    ///
    /// Once cancelled, the current `TimerCallback` will not be triggered again.
    pub(crate) fn cancel(&self) {
        if let Some(timer_callback) = self.inner.timer_callback.upgrade() {
            self.timer.timer_manager.cancel(&timer_callback);
        }
    }

    /// Returns the current expired time of this timer.
    pub(crate) fn expired_time(&self) -> Duration {
        let timer_callback = self.inner.timer_callback.upgrade();
        timer_callback
            .and_then(|callback| (!callback.is_cancelled()).then_some(callback.expired_time))
            .unwrap_or(Duration::ZERO)
    }

    /// Returns the remain time to expiration of this timer.
    ///
    /// If the timer has not been set, this method
    /// will return `Duration::ZERO`.
    pub(crate) fn remain(&self) -> Duration {
        let callback = self.inner.timer_callback.upgrade();
        let now = if callback.as_ref().is_some_and(|callback| callback.relative_clock) {
            self.timer.timer_manager.relative_clock.as_ref().unwrap().read_time()
        } else {
            self.timer.timer_manager.clock.read_time()
        };
        let expired_time = self.expired_time();
        if expired_time > now {
            expired_time - now
        } else {
            Duration::ZERO
        }
    }

    /// Returns the interval time of the current timer.
    pub(crate) fn interval(&self) -> Duration {
        self.inner.interval
    }
}

impl Timer {
    /// Creates a `Timer` instance from a [`TimerManager`].
    /// This timer will be managed by the `TimerManager`.
    ///
    /// Note that if the callback instructions involves sleep, users should put these instructions
    /// into something like `WorkQueue` to avoid sleeping during system timer interruptions.
    fn new<F>(registered_callback: F, timer_manager: Arc<TimerManager>) -> Arc<Self>
    where
        F: Fn(TimerGuard) + Send + Sync + 'static,
    {
        Arc::new(Self {
            inner: SpinLock::new(TimerInner::default()),
            timer_manager,
            registered_callback: Box::new(registered_callback),
        })
    }

    /// Locks the timer and returns a [`TimerGuard`] for exclusive access.
    pub(crate) fn lock(self: &Arc<Self>) -> TimerGuard<'_> {
        TimerGuard {
            inner: self.inner.disable_irq().lock(),
            timer: self,
        }
    }

    /// Returns a reference to the [`TimerManager`] which manages
    /// the current timer.
    pub(crate) fn timer_manager(&self) -> &Arc<TimerManager> {
        &self.timer_manager
    }
}

impl Drop for Timer {
    fn drop(&mut self) {
        let timer_callback = self.inner.disable_irq().lock().timer_callback.upgrade();
        if let Some(timer_callback) = timer_callback {
            self.timer_manager.cancel(&timer_callback);
        }
    }
}

/// `TimerManager` is used to create timers and manage their expiries. It holds a clock and can
/// create [`Timer`]s based on this clock.
///
/// These created `Timer`s will hold an `Arc` pointer to this manager, hence this manager
/// will be actually dropped after all the created timers have been dropped.
pub(crate) struct TimerManager {
    clock: Arc<dyn Clock>,
    timer_callbacks: SpinLock<BTreeMap<TimerKey, Arc<TimerCallback>>>,
    relative_clock: Option<Arc<dyn Clock>>,
    relative_timer_callbacks: SpinLock<BTreeMap<TimerKey, Arc<TimerCallback>>>,
}

/// The expiry time of a callback, made unique by the callback's address while it is queued.
type TimerKey = (Duration, usize);

impl TimerManager {
    /// Creates a `TimerManager` instance from a clock.
    pub(crate) fn new(clock: Arc<dyn Clock>) -> Arc<Self> {
        Arc::new(Self {
            clock,
            timer_callbacks: SpinLock::new(BTreeMap::new()),
            relative_clock: None,
            relative_timer_callbacks: SpinLock::new(BTreeMap::new()),
        })
    }

    pub(crate) fn new_realtime(clock: Arc<dyn Clock>, relative_clock: Arc<dyn Clock>) -> Arc<Self> {
        Arc::new(Self {
            clock,
            timer_callbacks: SpinLock::new(BTreeMap::new()),
            relative_clock: Some(relative_clock),
            relative_timer_callbacks: SpinLock::new(BTreeMap::new()),
        })
    }

    /// Returns the clock associated with this timer manager.
    pub(crate) fn clock(&self) -> &Arc<dyn Clock> {
        &self.clock
    }

    /// Returns whether a given `timeout` is expired.
    pub(crate) fn is_expired_timeout(&self, timeout: &Timeout) -> bool {
        match timeout {
            Timeout::After(duration) => *duration == Duration::ZERO,
            Timeout::When(duration) => {
                let now = self.clock.read_time();
                now >= *duration
            }
        }
    }

    fn insert(&self, timer_callback: Arc<TimerCallback>) {
        let callbacks = if timer_callback.relative_clock { &self.relative_timer_callbacks } else { &self.timer_callbacks };
        callbacks.disable_irq().lock().insert(timer_callback.key(), timer_callback);
    }

    /// Cancels the callback and removes it from the queue so that it does not outlive the wait
    /// that armed it.
    fn cancel(&self, timer_callback: &TimerCallback) {
        timer_callback.cancel();
        let callbacks = if timer_callback.relative_clock { &self.relative_timer_callbacks } else { &self.timer_callbacks };
        callbacks.disable_irq().lock().remove(&timer_callback.key());
    }

    /// Checks and processes the managed timers.
    ///
    /// If any of the timers have timed out, call the corresponding callback functions.
    pub(crate) fn process_expired_timers(&self) {
        if let Some(clock) = &self.relative_clock {
            crate::time::timerfd::with_clock_step_lock(|| {
                self.process_queue(&self.timer_callbacks, &self.clock);
                self.process_queue(&self.relative_timer_callbacks, clock);
            });
        } else {
            self.process_queue(&self.timer_callbacks, &self.clock);
        }
    }

    fn process_queue(&self, queue: &SpinLock<BTreeMap<TimerKey, Arc<TimerCallback>>>, clock: &Arc<dyn Clock>) {
        let callbacks = {
            let mut timeout_list = queue.disable_irq().lock();
            if timeout_list.is_empty() {
                return;
            }

            let mut callbacks = Vec::new();
            let current_time = clock.read_time();
            while let Some(entry) = timeout_list.first_entry() {
                if entry.key().0 > current_time {
                    break;
                }
                let t = entry.remove();
                if !t.is_cancelled() {
                    callbacks.push(t);
                }
            }
            callbacks
        };

        for callback in callbacks {
            callback.call();
        }
    }

    /// Creates an [`Timer`], which will be managed by this `TimerManager`.
    pub(crate) fn create_timer<F>(self: &Arc<Self>, function: F) -> Arc<Timer>
    where
        F: Fn(TimerGuard) + Send + Sync + 'static,
    {
        Timer::new(function, self.clone())
    }
}

/// A `TimerCallback` can be used to execute a timer callback function.
struct TimerCallback {
    expired_time: Duration,
    timer: Weak<Timer>,
    is_cancelled: AtomicBool,
    relative_clock: bool,
}

impl TimerCallback {
    /// Creates an instance of `TimerCallback`.
    fn new(timeout: Duration, timer: Weak<Timer>, relative_clock: bool) -> Self {
        Self {
            expired_time: timeout,
            timer,
            is_cancelled: AtomicBool::new(false),
            relative_clock,
        }
    }

    /// Cancels a `TimerCallback`. If the callback function has not been called,
    /// it will never be called again.
    fn cancel(&self) {
        self.is_cancelled.store(true, Ordering::Release);
    }

    fn key(&self) -> TimerKey {
        (self.expired_time, self as *const Self as usize)
    }

    // Returns whether the `TimerCallback` is cancelled.
    fn is_cancelled(&self) -> bool {
        self.is_cancelled.load(Ordering::Acquire)
    }

    fn call(&self) {
        let Some(timer) = self.timer.upgrade() else {
            return;
        };

        let mut timer_guard = timer.lock();

        if self.is_cancelled() {
            // The callback is cancelled.
            return;
        }

        let interval = timer_guard.interval();
        if interval != Duration::ZERO {
            let next = if !self.relative_clock && timer.timer_manager.relative_clock.is_some() {
                Timeout::When(timer.timer_manager.clock.read_time() + interval)
            } else {
                Timeout::After(interval)
            };
            timer_guard.set_timeout(next);
        }

        // Pass the `timer_guard` guard to the callback, allowing it to prevent race conditions.
        // The callback may choose to use the guard or drop it if not needed.
        (timer.registered_callback)(timer_guard);
    }
}
