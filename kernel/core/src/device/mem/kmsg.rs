// SPDX-License-Identifier: MPL-2.0

//! The kernel message ring behind `/dev/kmsg`.
//!
//! The ring holds the records that user space writes to `/dev/kmsg`. Asterinas prints its own
//! log to the console and does not add it to the ring.
//!
//! Reference: <https://elixir.bootlin.com/linux/v7.1/source/kernel/printk/printk.c> (`devkmsg_*`).

use alloc::format;

use aster_time::read_raw_monotonic_time;

use crate::{
    events::IoEvents,
    fs::{
        file::{PerOpenFileOps, SeekFrom, StatusFlags},
        vfs::inode::FileOps,
    },
    prelude::*,
    process::signal::{PollHandle, Pollable, Pollee},
};

/// The text that the ring holds before it drops its oldest records (`1 << CONFIG_LOG_BUF_SHIFT`).
const RING_TEXT_CAPACITY: usize = 1 << 17;

/// The longest write that forms one record (`PRINTKRB_RECORD_MAX`).
const WRITE_LIMIT: usize = 1024;

/// The level of a written record without a priority prefix (`CONFIG_MESSAGE_LOGLEVEL_DEFAULT`).
const DEFAULT_LEVEL: u32 = 4;

/// The facility of a written record whose prefix names none (`LOG_USER`).
const USER_FACILITY: u32 = 1;

struct Record {
    sequence: u64,
    microseconds: u64,
    priority: u32,
    text: Vec<u8>,
}

impl Record {
    /// Formats the record as one read of `/dev/kmsg` returns it.
    fn render(&self) -> Vec<u8> {
        let mut line = format!(
            "{},{},{},-;",
            self.priority, self.sequence, self.microseconds
        )
        .into_bytes();
        for &byte in &self.text {
            if byte < b' ' || byte >= 0x7f || byte == b'\\' {
                line.extend_from_slice(format!("\\x{:02x}", byte).as_bytes());
            } else {
                line.push(byte);
            }
        }
        line.push(b'\n');
        line
    }
}

struct Ring {
    records: VecDeque<Record>,
    next_sequence: u64,
    text_len: usize,
    readers: Vec<Weak<Reader>>,
}

static RING: Mutex<Ring> = Mutex::new(Ring {
    records: VecDeque::new(),
    next_sequence: 0,
    text_len: 0,
    readers: Vec::new(),
});

impl Ring {
    fn first_sequence(&self) -> u64 {
        self.records
            .front()
            .map_or(self.next_sequence, |record| record.sequence)
    }

    fn record(&self, sequence: u64) -> Option<&Record> {
        let index = sequence.checked_sub(self.first_sequence())?;
        self.records.get(usize::try_from(index).ok()?)
    }

    fn push(&mut self, priority: u32, text: Vec<u8>) {
        self.text_len += text.len();
        self.records.push_back(Record {
            sequence: self.next_sequence,
            microseconds: read_raw_monotonic_time().as_micros() as u64,
            priority,
            text,
        });
        self.next_sequence += 1;
        while self.text_len > RING_TEXT_CAPACITY
            && let Some(dropped) = self.records.pop_front()
        {
            self.text_len -= dropped.text.len();
        }
    }

    fn live_readers(&mut self) -> Vec<Arc<Reader>> {
        self.readers.retain(|reader| reader.strong_count() > 0);
        self.readers.iter().filter_map(Weak::upgrade).collect()
    }
}

/// Splits a write into the priority and the text of its record.
///
/// A leading `<N>` sets the level and, unless its facility is zero, the facility. One trailing
/// newline ends the record and is not part of it.
fn parse_write(line: &[u8]) -> (u32, &[u8]) {
    let mut level = DEFAULT_LEVEL;
    let mut facility = USER_FACILITY;
    let mut text = line;
    if let Some(rest) = line.strip_prefix(b"<") {
        let digits = rest.iter().take_while(|byte| byte.is_ascii_digit()).count();
        if rest.get(digits) == Some(&b'>') {
            let value = rest[..digits].iter().fold(0u64, |value, digit| {
                value.wrapping_mul(10).wrapping_add(u64::from(digit - b'0'))
            });
            level = (value & 7) as u32;
            let named_facility = ((value >> 3) & 0xff) as u32;
            if named_facility != 0 {
                facility = named_facility;
            }
            text = &rest[digits + 1..];
        }
    }
    let text = text.strip_suffix(b"\n").unwrap_or(text);
    ((facility << 3) | level, text)
}

struct Reader {
    cursor: Mutex<u64>,
    pollee: Pollee,
}

/// An open `/dev/kmsg`, which reads the ring from its own position.
pub(super) struct KmsgFile {
    reader: Arc<Reader>,
}

impl KmsgFile {
    /// Opens the ring at its oldest record.
    pub(super) fn open() -> Self {
        let mut ring = RING.lock();
        let reader = Arc::new(Reader {
            cursor: Mutex::new(ring.first_sequence()),
            pollee: Pollee::new(),
        });
        let _ = ring.live_readers();
        ring.readers.push(Arc::downgrade(&reader));
        Self { reader }
    }

    fn check_io_events(&self) -> IoEvents {
        let ring = RING.lock();
        let cursor = *self.reader.cursor.lock();
        if cursor < ring.first_sequence() {
            IoEvents::IN | IoEvents::ERR | IoEvents::PRI
        } else if cursor < ring.next_sequence {
            IoEvents::IN
        } else {
            IoEvents::empty()
        }
    }

    fn try_read(&self, writer: &mut VmWriter) -> Result<usize> {
        let ring = RING.lock();
        let mut cursor = self.reader.cursor.lock();
        let first = ring.first_sequence();
        if *cursor < first {
            *cursor = first;
            drop(cursor);
            self.reader.pollee.invalidate();
            return_errno_with_message!(Errno::EPIPE, "the ring dropped records before they were read");
        }
        let Some(record) = ring.record(*cursor) else {
            return_errno_with_message!(Errno::EAGAIN, "the ring has no record to read");
        };
        let line = record.render();
        *cursor += 1;
        drop(cursor);
        self.reader.pollee.invalidate();
        if line.len() > writer.avail() {
            return_errno_with_message!(
                Errno::EINVAL,
                "the buffer is too short for the record, which is now skipped"
            );
        }
        writer
            .write_fallible(&mut VmReader::from(line.as_slice()))
            .map_err(|(error, _)| error)?;
        Ok(line.len())
    }
}

impl Pollable for KmsgFile {
    fn poll(&self, mask: IoEvents, poller: Option<&mut PollHandle>) -> IoEvents {
        self.reader
            .pollee
            .poll_with(mask, poller, || self.check_io_events())
    }
}

impl FileOps for KmsgFile {
    fn read_at(
        &self,
        _offset: usize,
        writer: &mut VmWriter,
        status_flags: StatusFlags,
    ) -> Result<usize> {
        if status_flags.contains(StatusFlags::O_NONBLOCK) {
            self.try_read(writer)
        } else {
            self.wait_events(IoEvents::IN, None, || self.try_read(writer))
        }
    }

    fn write_at(
        &self,
        _offset: usize,
        reader: &mut VmReader,
        _status_flags: StatusFlags,
    ) -> Result<usize> {
        let len = reader.remain();
        if len > WRITE_LIMIT {
            return_errno_with_message!(Errno::EINVAL, "the record is too long");
        }
        let mut buffer = vec![0u8; len];
        reader
            .read_fallible(&mut VmWriter::from(buffer.as_mut_slice()))
            .map_err(|(error, _)| error)?;
        let (priority, text) = parse_write(&buffer);

        let readers = {
            let mut ring = RING.lock();
            ring.push(priority, text.to_vec());
            ring.live_readers()
        };
        for reader in readers {
            reader.pollee.notify(IoEvents::IN);
        }
        Ok(len)
    }
}

impl PerOpenFileOps for KmsgFile {
    fn check_seekable(&self) -> Result<()> {
        Ok(())
    }

    fn is_offset_aware(&self) -> bool {
        false
    }

    fn seek_position(&self, pos: SeekFrom) -> Option<Result<usize>> {
        let ring = RING.lock();
        let sequence = match pos {
            SeekFrom::Start(0) => ring.first_sequence(),
            SeekFrom::End(0) => ring.next_sequence,
            SeekFrom::Current(0) => {
                return Some(Err(Error::with_message(
                    Errno::EINVAL,
                    "the ring has no current position to seek from",
                )));
            }
            SeekFrom::Start(_) | SeekFrom::End(_) | SeekFrom::Current(_) => {
                return Some(Err(Error::with_message(
                    Errno::ESPIPE,
                    "the ring is positioned only at its start or its end",
                )));
            }
        };
        *self.reader.cursor.lock() = sequence;
        drop(ring);
        self.reader.pollee.invalidate();
        Some(Ok(0))
    }
}

#[cfg(ktest)]
mod test {
    use ostd::prelude::ktest;

    use super::*;

    #[ktest]
    fn a_write_without_a_prefix_is_a_user_warning_without_its_newline() {
        assert_eq!(parse_write(b"plain record\n"), (12, &b"plain record"[..]));
    }

    #[ktest]
    fn a_prefix_sets_the_level_and_a_named_facility() {
        assert_eq!(parse_write(b"<29>daemon notice"), (29, &b"daemon notice"[..]));
        assert_eq!(parse_write(b"<2>kernel facility"), (10, &b"kernel facility"[..]));
        assert_eq!(parse_write(b"<>empty prefix"), (8, &b"empty prefix"[..]));
    }

    #[ktest]
    fn an_unterminated_prefix_stays_in_the_text() {
        assert_eq!(parse_write(b"<6open prefix"), (12, &b"<6open prefix"[..]));
    }

    #[ktest]
    fn a_record_escapes_control_bytes_and_backslashes() {
        let record = Record {
            sequence: 7,
            microseconds: 42,
            priority: 14,
            text: b"tab\there\\back".to_vec(),
        };
        assert_eq!(record.render(), b"14,7,42,-;tab\\x09here\\x5cback\n");
    }
}
