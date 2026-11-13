// SPDX-License-Identifier: MPL-2.0

use alloc::format;

use aster_logger::ring::{self, ReadFailure};
use ostd::mm::VmIo;

use super::SyscallReturn;
use crate::{
    prelude::*,
    security::syslog::{
        SYSLOG_ACTION_READ_ALL, SYSLOG_ACTION_SIZE_BUFFER, check_syslog_permissions,
    },
};

const SYSLOG_ACTION_CLOSE: i32 = 0;
const SYSLOG_ACTION_OPEN: i32 = 1;

/// The capacity that `SYSLOG_ACTION_SIZE_BUFFER` reports, the size of the ring of `aster_logger`.
const LOG_BUF_LEN: i32 = 1 << 17;

pub(super) fn sys_syslog(action: i32, buf: Vaddr, len: i32, ctx: &Context) -> Result<SyscallReturn> {
    debug!("[sys_syslog]: action = {}, buf = {:#x}, len = {}", action, buf, len);

    check_syslog_permissions(action)?;

    match action {
        SYSLOG_ACTION_CLOSE | SYSLOG_ACTION_OPEN => Ok(SyscallReturn::Return(0)),
        SYSLOG_ACTION_READ_ALL => {
            if buf == 0 || len < 0 {
                return_errno_with_message!(Errno::EINVAL, "the buffer or its length is invalid");
            }
            let text = read_all(len as usize);
            ctx.user_space().write_bytes(buf, &text)?;
            Ok(SyscallReturn::Return(text.len() as isize))
        }
        SYSLOG_ACTION_SIZE_BUFFER => Ok(SyscallReturn::Return(LOG_BUF_LEN as isize)),
        2 | 4 | 5 | 6 | 7 | 8 | 9 => {
            return_errno_with_message!(Errno::ENOSYS, "the syslog action is not supported")
        }
        _ => return_errno_with_message!(Errno::EINVAL, "the syslog action is invalid"),
    }
}

/// Renders the newest whole records of the ring that fit in `limit` bytes.
fn read_all(limit: usize) -> Vec<u8> {
    let mut lines: Vec<Vec<u8>> = Vec::new();
    let mut cursor = ring::oldest();
    loop {
        match ring::read(&mut cursor) {
            Ok(record) => {
                let mut line = format!(
                    "<{}>[{:5}.{:06}] ",
                    record.priority,
                    record.microseconds / 1_000_000,
                    record.microseconds % 1_000_000
                )
                .into_bytes();
                line.extend_from_slice(record.text());
                line.push(b'\n');
                lines.push(line);
            }
            Err(ReadFailure::Overrun) => lines.clear(),
            Err(ReadFailure::Drained) => break,
        }
    }

    let mut total = 0usize;
    let mut first = lines.len();
    while first > 0 && total + lines[first - 1].len() <= limit {
        first -= 1;
        total += lines[first].len();
    }
    lines.drain(first..).flatten().collect::<Vec<u8>>()
}
