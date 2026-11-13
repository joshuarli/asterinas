// SPDX-License-Identifier: MPL-2.0

use crate::{
    net::socket::netlink::receiver::QueueableMessage,
    prelude::*,
    util::MultiWrite,
};

pub(crate) struct GenericMessage(pub(super) Vec<u8>);

impl GenericMessage {
    pub(super) fn write_to(&self, writer: &mut dyn MultiWrite) -> Result<()> {
        writer.write(&mut VmReader::from(self.0.as_slice()))?;
        Ok(())
    }
}

impl QueueableMessage for GenericMessage {
    fn total_len(&self) -> usize {
        self.0.len()
    }
}
