// SPDX-License-Identifier: MPL-2.0

//! Block I/O submission accounting.

use core::sync::atomic::{AtomicU64, Ordering};

use crate::bio::BioType;

static READ_SECTORS: AtomicU64 = AtomicU64::new(0);
static WRITE_SECTORS: AtomicU64 = AtomicU64::new(0);

pub(crate) fn account_submission(type_: BioType, sectors: u64) {
    match type_ {
        BioType::Read => &READ_SECTORS,
        BioType::Write => &WRITE_SECTORS,
        BioType::Flush => return,
    }
    .fetch_add(sectors, Ordering::Relaxed);
}

/// Returns the total submitted read and write sectors, respectively.
pub fn submitted_sectors() -> (u64, u64) {
    (
        READ_SECTORS.load(Ordering::Relaxed),
        WRITE_SECTORS.load(Ordering::Relaxed),
    )
}

/// Returns the total submitted read and write data in KiB, respectively.
pub fn submitted_kib() -> (u64, u64) {
    let (read, write) = submitted_sectors();
    (read / 2, write / 2)
}

use alloc::sync::Arc;
use ostd::{sync::{LocalIrqDisabled, SpinLock}, timer::Jiffies};

/// A snapshot of completed I/O and current request activity, with times in milliseconds
/// and data sizes in 512-byte sectors.
#[derive(Clone, Copy, Debug, Default)]
pub struct IoStatsSnapshot {
    pub reads: u64,
    pub reads_merged: u64,
    pub sectors_read: u64,
    pub read_ms: u64,
    pub writes: u64,
    pub writes_merged: u64,
    pub sectors_written: u64,
    pub write_ms: u64,
    pub in_flight: u64,
    pub io_ms: u64,
    pub weighted_io_ms: u64,
}

#[derive(Debug, Default)]
struct State {
    snapshot: IoStatsSnapshot,
    last_ns: u128,
    busy_ns: u128,
    weighted_ns: u128,
    read_ns: u128,
    write_ns: u128,
}

impl State {
    fn advance(&mut self, now: u128) -> u128 {
        let now = now.max(self.last_ns);
        let elapsed = now - self.last_ns;
        if self.snapshot.in_flight != 0 {
            self.busy_ns = self.busy_ns.saturating_add(elapsed);
            self.weighted_ns = self.weighted_ns.saturating_add(elapsed.saturating_mul(self.snapshot.in_flight as u128));
        }
        self.last_ns = now;
        now
    }

    fn snapshot(&mut self, now: u128) -> IoStatsSnapshot {
        self.advance(now);
        let mut snapshot = self.snapshot;
        snapshot.read_ms = millis(self.read_ns);
        snapshot.write_ms = millis(self.write_ns);
        snapshot.io_ms = millis(self.busy_ns);
        snapshot.weighted_io_ms = millis(self.weighted_ns);
        snapshot
    }
}

fn millis(ns: u128) -> u64 {
    (ns / 1_000_000).min(u64::MAX as u128) as u64
}

fn now_ns() -> u128 {
    Jiffies::elapsed().as_duration().as_nanos()
}

#[derive(Debug)]
pub(crate) struct IoStats {
    state: SpinLock<State, LocalIrqDisabled>,
}

impl IoStats {
    pub(crate) fn new() -> Self {
        Self { state: SpinLock::new(State::default()) }
    }

    pub(crate) fn snapshot(&self) -> IoStatsSnapshot {
        self.state.lock().snapshot(now_ns())
    }

    pub(crate) fn start(self: &Arc<Self>, type_: BioType, sectors: u64) -> Option<IoRecord> {
        self.start_at(type_, sectors, now_ns())
    }

    fn start_at(self: &Arc<Self>, type_: BioType, sectors: u64, now: u128) -> Option<IoRecord> {
        if type_ == BioType::Flush { return None; }
        let mut state = self.state.lock();
        let start_ns = state.advance(now);
        state.snapshot.in_flight += 1;
        Some(IoRecord { stats: self.clone(), type_, sectors, start_ns, active: true })
    }
}

impl Default for IoStats {
    fn default() -> Self { Self::new() }
}

#[derive(Debug)]
pub(crate) struct IoRecord {
    stats: Arc<IoStats>,
    type_: BioType,
    sectors: u64,
    start_ns: u128,
    active: bool,
}

impl IoRecord {
    pub(crate) fn belongs_to(&self, stats: &Arc<IoStats>) -> bool {
        Arc::ptr_eq(&self.stats, stats)
    }

    pub(crate) fn merge(&mut self, sectors: u64) {
        self.sectors = self.sectors.saturating_add(sectors);
        let mut state = self.stats.state.lock();
        match self.type_ {
            BioType::Read => state.snapshot.reads_merged = state.snapshot.reads_merged.saturating_add(1),
            BioType::Write => state.snapshot.writes_merged = state.snapshot.writes_merged.saturating_add(1),
            BioType::Flush => unreachable!(),
        }
    }

    pub(crate) fn complete(mut self) {
        self.finish_at(now_ns(), true);
    }

    fn finish_at(&mut self, now: u128, completed: bool) {
        if !self.active { return; }
        let mut state = self.stats.state.lock();
        let now = state.advance(now);
        state.snapshot.in_flight -= 1;
        if completed {
            let elapsed = now.saturating_sub(self.start_ns);
            match self.type_ {
                BioType::Read => {
                    state.snapshot.reads = state.snapshot.reads.saturating_add(1);
                    state.snapshot.sectors_read = state.snapshot.sectors_read.saturating_add(self.sectors);
                    state.read_ns = state.read_ns.saturating_add(elapsed);
                }
                BioType::Write => {
                    state.snapshot.writes = state.snapshot.writes.saturating_add(1);
                    state.snapshot.sectors_written = state.snapshot.sectors_written.saturating_add(self.sectors);
                    state.write_ns = state.write_ns.saturating_add(elapsed);
                }
                BioType::Flush => unreachable!(),
            }
        }
        self.active = false;
    }
}

impl Drop for IoRecord {
    fn drop(&mut self) { self.finish_at(now_ns(), false); }
}

#[cfg(ktest)]
mod tests {
    use alloc::sync::Arc;
    use ostd::prelude::ktest;
    use super::{BioType, IoStats};

    #[ktest]
    fn overlapping_requests_measure_busy_and_weighted_time() {
        let stats = Arc::new(IoStats::new());
        let mut read = stats.start_at(BioType::Read, 8, 1_000_000).unwrap();
        let mut write = stats.start_at(BioType::Write, 16, 2_000_000).unwrap();
        read.merge(4);
        let active = stats.state.lock().snapshot(3_000_000);
        assert_eq!(active.in_flight, 2);
        assert_eq!(active.io_ms, 2);
        assert_eq!(active.weighted_io_ms, 3);
        read.finish_at(4_000_000, true);
        write.finish_at(5_000_000, true);
        let done = stats.state.lock().snapshot(5_000_000);
        assert_eq!(done.in_flight, 0);
        assert_eq!(done.reads, 1);
        assert_eq!(done.reads_merged, 1);
        assert_eq!(done.sectors_read, 12);
        assert_eq!(done.read_ms, 3);
        assert_eq!(done.writes, 1);
        assert_eq!(done.sectors_written, 16);
        assert_eq!(done.write_ms, 3);
        assert_eq!(done.io_ms, 4);
        assert_eq!(done.weighted_io_ms, 6);
    }

    #[ktest]
    fn cancellation_does_not_report_completion_and_flush_is_excluded() {
        let stats = Arc::new(IoStats::new());
        assert!(stats.start_at(BioType::Flush, 0, 0).is_none());
        let mut record = stats.start_at(BioType::Write, 8, 0).unwrap();
        record.finish_at(1_000_000, false);
        let snapshot = stats.state.lock().snapshot(2_000_000);
        assert_eq!(snapshot.in_flight, 0);
        assert_eq!(snapshot.writes, 0);
        assert_eq!(snapshot.sectors_written, 0);
        assert_eq!(snapshot.io_ms, 1);
    }
}
