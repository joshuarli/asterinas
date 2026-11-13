// SPDX-License-Identifier: MPL-2.0

use super::controller::{DumpCursor, DUMP_PACKET_SIZE};
use crate::{
    net::socket::netlink::receiver::QueueableMessage,
    prelude::*,
    util::MultiWrite,
};

pub(crate) enum SockDiagMessage {
    Single(Vec<u8>),
    Dump(Mutex<Dump>),
}

pub(crate) struct Dump {
    pub(super) bytes: Vec<u8>,
    pub(super) cursor: DumpCursor,
}

impl SockDiagMessage {
    pub(super) fn write_to(&self, writer: &mut dyn MultiWrite) -> Result<()> {
        match self {
            Self::Single(bytes) => { writer.write(&mut VmReader::from(bytes.as_slice()))?; }
            Self::Dump(dump) => { writer.write(&mut VmReader::from(dump.lock().bytes.as_slice()))?; }
        }
        Ok(())
    }

    pub(super) fn advance(&self) -> bool {
        match self {
            Self::Single(_) => true,
            Self::Dump(dump) => {
                let mut dump = dump.lock();
                if dump.cursor.finished { return true; }
                dump.bytes = dump.cursor.packet();
                false
            }
        }
    }
}

impl QueueableMessage for SockDiagMessage {
    fn total_len(&self) -> usize {
        match self {
            Self::Single(bytes) => bytes.len(),
            Self::Dump(dump) => dump.lock().bytes.len(),
        }
    }

    fn queue_len(&self) -> usize {
        match self {
            Self::Single(bytes) => bytes.len(),
            Self::Dump(_) => DUMP_PACKET_SIZE,
        }
    }
}
