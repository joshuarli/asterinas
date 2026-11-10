// SPDX-License-Identifier: MPL-2.0

//! The kernel message ring that `/dev/kmsg` reads.
//!
//! The ring holds the kernel's own log records and the records that user space writes. A kernel
//! record may be added from any context, so the ring lives in static memory behind an IRQ-disabled
//! spin lock and adding a record never allocates.
//!
//! Reference: <https://elixir.bootlin.com/linux/v7.1/source/kernel/printk/printk.c>.

use core::{
    fmt::{self, Write},
    sync::atomic::{AtomicBool, Ordering},
};

use ostd::{
    sync::{LocalIrqDisabled, SpinLock},
    timer::Jiffies,
};

/// The bytes that the ring holds before it drops its oldest records (`1 << CONFIG_LOG_BUF_SHIFT`).
const RING_CAPACITY: usize = 1 << 17;

/// The longest text of one record (`PRINTKRB_RECORD_MAX`).
pub const RECORD_TEXT_LIMIT: usize = 1024;

const HEADER_LEN: usize = 24;

/// The position of a reader in the ring.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Cursor {
    sequence: u64,
    offset: usize,
}

/// What a reader at a cursor finds in the ring.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Readiness {
    /// The ring dropped records that the reader has not read.
    Overrun,
    /// A record waits at the cursor.
    Ready,
    /// The reader has read every record.
    Drained,
}

/// One record copied out of the ring.
pub struct RecordCopy {
    /// The record's sequence number.
    pub sequence: u64,
    /// The time the record was added, in microseconds since boot.
    pub microseconds: u64,
    /// The record's facility and level, as `(facility << 3) | level`.
    pub priority: u32,
    text: [u8; RECORD_TEXT_LIMIT],
    text_len: usize,
}

impl RecordCopy {
    /// Returns the record's text.
    pub fn text(&self) -> &[u8] {
        &self.text[..self.text_len]
    }
}

/// Why a read at a cursor returned no record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReadFailure {
    /// The ring dropped records that the reader has not read; the cursor now names the oldest one.
    Overrun,
    /// The reader has read every record.
    Drained,
}

struct Ring<const CAPACITY: usize> {
    bytes: [u8; CAPACITY],
    head: usize,
    used: usize,
    first_sequence: u64,
    next_sequence: u64,
}

static RING: SpinLock<Ring<RING_CAPACITY>, LocalIrqDisabled> = SpinLock::new(Ring {
    bytes: [0; RING_CAPACITY],
    head: 0,
    used: 0,
    first_sequence: 0,
    next_sequence: 0,
});

static KERNEL_RECORD_PENDING: AtomicBool = AtomicBool::new(false);

impl<const CAPACITY: usize> Ring<CAPACITY> {
    fn tail(&self) -> usize {
        (self.head + self.used) % CAPACITY
    }

    fn copy_in(&mut self, offset: usize, data: &[u8]) {
        let first = data.len().min(CAPACITY - offset);
        self.bytes[offset..offset + first].copy_from_slice(&data[..first]);
        self.bytes[..data.len() - first].copy_from_slice(&data[first..]);
    }

    fn copy_out(&self, offset: usize, data: &mut [u8]) {
        let first = data.len().min(CAPACITY - offset);
        data[..first].copy_from_slice(&self.bytes[offset..offset + first]);
        let rest = data.len() - first;
        data[first..].copy_from_slice(&self.bytes[..rest]);
    }

    fn header(&self, offset: usize) -> (u64, u64, u32, usize) {
        let mut header = [0u8; HEADER_LEN];
        self.copy_out(offset, &mut header);
        let field = |range: core::ops::Range<usize>| {
            let mut value = [0u8; 8];
            value[..range.len()].copy_from_slice(&header[range]);
            u64::from_le_bytes(value)
        };
        (
            field(0..8),
            field(8..16),
            field(16..20) as u32,
            field(20..24) as usize,
        )
    }

    fn push(&mut self, priority: u32, text: &[u8]) {
        let text = &text[..text.len().min(RECORD_TEXT_LIMIT)];
        let record_len = HEADER_LEN + text.len();
        while CAPACITY - self.used < record_len {
            let (_, _, _, dropped_len) = self.header(self.head);
            let dropped = HEADER_LEN + dropped_len;
            self.head = (self.head + dropped) % CAPACITY;
            self.used -= dropped;
            self.first_sequence += 1;
        }

        let microseconds = Jiffies::elapsed().as_duration().as_micros() as u64;
        let mut header = [0u8; HEADER_LEN];
        header[0..8].copy_from_slice(&self.next_sequence.to_le_bytes());
        header[8..16].copy_from_slice(&microseconds.to_le_bytes());
        header[16..20].copy_from_slice(&priority.to_le_bytes());
        header[20..24].copy_from_slice(&(text.len() as u32).to_le_bytes());
        let tail = self.tail();
        self.copy_in(tail, &header);
        self.copy_in((tail + HEADER_LEN) % CAPACITY, text);
        self.used += record_len;
        self.next_sequence += 1;
    }

    fn readiness(&self, cursor: Cursor) -> Readiness {
        if cursor.sequence < self.first_sequence {
            Readiness::Overrun
        } else if cursor.sequence < self.next_sequence {
            Readiness::Ready
        } else {
            Readiness::Drained
        }
    }

    fn oldest(&self) -> Cursor {
        Cursor {
            sequence: self.first_sequence,
            offset: self.head,
        }
    }

    fn newest(&self) -> Cursor {
        Cursor {
            sequence: self.next_sequence,
            offset: self.tail(),
        }
    }

    fn read(&self, cursor: &mut Cursor) -> Result<RecordCopy, ReadFailure> {
        match self.readiness(*cursor) {
            Readiness::Overrun => {
                *cursor = self.oldest();
                return Err(ReadFailure::Overrun);
            }
            Readiness::Drained => return Err(ReadFailure::Drained),
            Readiness::Ready => {}
        }
        let (sequence, microseconds, priority, text_len) = self.header(cursor.offset);
        let mut record = RecordCopy {
            sequence,
            microseconds,
            priority,
            text: [0; RECORD_TEXT_LIMIT],
            text_len,
        };
        self.copy_out(
            (cursor.offset + HEADER_LEN) % CAPACITY,
            &mut record.text[..text_len],
        );
        *cursor = Cursor {
            sequence: sequence + 1,
            offset: (cursor.offset + HEADER_LEN + text_len) % CAPACITY,
        };
        Ok(record)
    }
}

/// Returns the cursor of the oldest record in the ring.
pub fn oldest() -> Cursor {
    RING.lock().oldest()
}

/// Returns the cursor past the newest record in the ring.
pub fn newest() -> Cursor {
    RING.lock().newest()
}

/// Reports what a reader at `cursor` finds in the ring.
pub fn readiness(cursor: Cursor) -> Readiness {
    RING.lock().readiness(cursor)
}

/// Copies the record at `cursor` and advances `cursor` past it.
pub fn read(cursor: &mut Cursor) -> Result<RecordCopy, ReadFailure> {
    RING.lock().read(cursor)
}

/// Adds a record that user space wrote.
pub fn push_user(priority: u32, text: &[u8]) {
    RING.lock().push(priority, text);
}

/// Reports whether the kernel added records since the last call.
pub fn take_kernel_record_pending() -> bool {
    KERNEL_RECORD_PENDING.swap(false, Ordering::Acquire)
}

struct TextBuffer {
    bytes: [u8; RECORD_TEXT_LIMIT],
    len: usize,
}

impl Write for TextBuffer {
    fn write_str(&mut self, text: &str) -> fmt::Result {
        let room = RECORD_TEXT_LIMIT - self.len;
        let taken = text.len().min(room);
        self.bytes[self.len..self.len + taken].copy_from_slice(&text.as_bytes()[..taken]);
        self.len += taken;
        Ok(())
    }
}

/// Adds a kernel log record at `level`, whose facility is the kernel's (zero).
pub(crate) fn push_kernel(level: u8, prefix: &str, args: &fmt::Arguments) {
    let mut text = TextBuffer {
        bytes: [0; RECORD_TEXT_LIMIT],
        len: 0,
    };
    let _ = write!(text, "{}{}", prefix, args);
    let line = &text.bytes[..text.len];
    let line = line.strip_suffix(b"\n").unwrap_or(line);
    RING.lock().push(u32::from(level), line);
    KERNEL_RECORD_PENDING.store(true, Ordering::Release);
}

#[cfg(ktest)]
mod test {
    use ostd::prelude::ktest;

    use super::*;

    const TEST_CAPACITY: usize = 4 * (HEADER_LEN + RECORD_TEXT_LIMIT) + 100;

    fn empty_ring() -> Ring<TEST_CAPACITY> {
        Ring {
            bytes: [0; TEST_CAPACITY],
            head: 0,
            used: 0,
            first_sequence: 0,
            next_sequence: 0,
        }
    }

    #[ktest]
    fn full_ring_drops_its_oldest_records_and_keeps_wrapped_text_whole() {
        let mut ring = empty_ring();
        let per_record = HEADER_LEN + RECORD_TEXT_LIMIT;
        let kept = TEST_CAPACITY / per_record;
        let mut behind = ring.newest();
        for index in 0..kept + 3 {
            ring.push(14, &[b'a' + index as u8; RECORD_TEXT_LIMIT]);
        }
        assert_eq!(ring.read(&mut behind).err(), Some(ReadFailure::Overrun));
        assert_eq!(behind, ring.oldest());
        for index in 3..kept + 3 {
            let record = ring.read(&mut behind).ok().unwrap();
            assert_eq!((record.sequence, record.priority), (index as u64, 14));
            assert!(record.text().iter().all(|&byte| byte == b'a' + index as u8));
        }
        assert_eq!(ring.read(&mut behind).err(), Some(ReadFailure::Drained));
        assert_eq!(behind, ring.newest());
    }

    #[ktest]
    fn a_record_keeps_at_most_the_text_limit() {
        let mut ring = empty_ring();
        let mut cursor = ring.newest();
        ring.push(6, &[b'z'; RECORD_TEXT_LIMIT + 5]);
        assert_eq!(ring.read(&mut cursor).ok().unwrap().text().len(), RECORD_TEXT_LIMIT);
    }
}
