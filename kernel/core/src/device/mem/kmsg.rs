// SPDX-License-Identifier: MPL-2.0

//! The kernel message ring behind `/dev/kmsg`.
//!
//! Reads return the kernel's own log records and the records that user space writes.
//!
//! Reference: <https://elixir.bootlin.com/linux/v7.1/source/kernel/printk/printk.c> (`devkmsg_*`).

use alloc::format;

use aster_logger::ring::{self, Cursor, ReadFailure, Readiness, RecordCopy};
use ostd::sync::LocalIrqDisabled;

use crate::{
    events::IoEvents,
    fs::{
        file::{PerOpenFileOps, SeekFrom, StatusFlags},
        vfs::inode::FileOps,
    },
    prelude::*,
    process::signal::{PollHandle, Pollable, Pollee},
};

/// The longest write that forms one record (`PRINTKRB_RECORD_MAX`).
const WRITE_LIMIT: usize = ring::RECORD_TEXT_LIMIT;

/// The level of a written record without a priority prefix (`CONFIG_MESSAGE_LOGLEVEL_DEFAULT`).
const DEFAULT_LEVEL: u32 = 4;

/// The facility of a written record whose prefix names none (`LOG_USER`).
const USER_FACILITY: u32 = 1;

/// Formats a record as one read of `/dev/kmsg` returns it.
fn render(record: &RecordCopy) -> Vec<u8> {
    let mut line = format!(
        "{},{},{},-;",
        record.priority, record.sequence, record.microseconds
    )
    .into_bytes();
    escape_into(&mut line, record.text());
    line.push(b'\n');
    line
}

fn escape_into(line: &mut Vec<u8>, text: &[u8]) {
    for &byte in text {
        if byte < b' ' || byte >= 0x7f || byte == b'\\' {
            line.extend_from_slice(format!("\\x{:02x}", byte).as_bytes());
        } else {
            line.push(byte);
        }
    }
}

static READERS: SpinLock<Vec<Weak<Reader>>, LocalIrqDisabled> = SpinLock::new(Vec::new());

fn live_readers() -> Vec<Arc<Reader>> {
    let mut readers = READERS.lock();
    readers.retain(|reader| reader.strong_count() > 0);
    readers.iter().filter_map(Weak::upgrade).collect()
}

fn notify_readers() {
    for reader in live_readers() {
        reader.pollee.notify(IoEvents::IN);
    }
}

pub(super) fn init() {
    ostd::timer::register_callback_on_cpu(|| {
        if ring::take_kernel_record_pending() {
            notify_readers();
        }
    });
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
    cursor: Mutex<Cursor>,
    pollee: Pollee,
}

/// An open `/dev/kmsg`, which reads the ring from its own position.
pub(super) struct KmsgFile {
    reader: Arc<Reader>,
}

impl KmsgFile {
    /// Opens the ring at its oldest record.
    pub(super) fn open() -> Self {
        let reader = Arc::new(Reader {
            cursor: Mutex::new(ring::oldest()),
            pollee: Pollee::new(),
        });
        let mut readers = READERS.lock();
        readers.retain(|reader| reader.strong_count() > 0);
        readers.push(Arc::downgrade(&reader));
        drop(readers);
        Self { reader }
    }

    fn check_io_events(&self) -> IoEvents {
        match ring::readiness(*self.reader.cursor.lock()) {
            Readiness::Overrun => IoEvents::IN | IoEvents::ERR | IoEvents::PRI,
            Readiness::Ready => IoEvents::IN,
            Readiness::Drained => IoEvents::empty(),
        }
    }

    fn try_read(&self, writer: &mut VmWriter) -> Result<usize> {
        let read = ring::read(&mut self.reader.cursor.lock());
        self.reader.pollee.invalidate();
        let record = match read {
            Ok(record) => record,
            Err(ReadFailure::Overrun) => return_errno_with_message!(
                Errno::EPIPE,
                "the ring dropped records before they were read"
            ),
            Err(ReadFailure::Drained) => {
                return_errno_with_message!(Errno::EAGAIN, "the ring has no record to read")
            }
        };
        let line = render(&record);
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
        ring::push_user(priority, text);
        notify_readers();
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
        let cursor = match pos {
            SeekFrom::Start(0) => ring::oldest(),
            SeekFrom::End(0) => ring::newest(),
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
        *self.reader.cursor.lock() = cursor;
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
        let mut line = Vec::new();
        escape_into(&mut line, b"tab\there\\back");
        assert_eq!(line, b"tab\\x09here\\x5cback");
    }
}
