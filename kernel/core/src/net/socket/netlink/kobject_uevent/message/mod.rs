// SPDX-License-Identifier: MPL-2.0

use core::str::FromStr;

use syn_uevent::SyntheticUevent;
use uevent::Uevent;

use crate::{
    net::socket::netlink::{
        NetlinkSocketAddr, receiver::QueueableMessage, table::MulticastMessage,
    },
    prelude::*,
    util::MultiWrite,
};

mod syn_uevent;
#[cfg(ktest)]
mod test;
mod uevent;

/// A uevent message.
///
/// Note that uevent messages are not the same as common netlink messages.
/// It does not have a netlink header.
#[derive(Clone, Debug)]
pub(crate) struct UeventMessage {
    uevent: String,
    src_addr: NetlinkSocketAddr,
}

impl UeventMessage {
    /// Creates a new uevent message.
    fn new(uevent: Uevent, src_addr: NetlinkSocketAddr) -> Self {
        Self {
            uevent: uevent.to_string(),
            src_addr,
        }
    }

    /// Creates the message a write of `command` to a device's `uevent` attribute produces.
    pub(crate) fn from_synthetic_command(
        command: &str,
        devpath: String,
        subsystem: String,
        envs: Vec<(String, String)>,
    ) -> Result<Self> {
        let synthetic = SyntheticUevent::from_str(command)?;
        let uevent = Uevent::new_from_syn(synthetic, devpath, subsystem, envs);
        Ok(Self::new(uevent, NetlinkSocketAddr::new_unspecified()))
    }

    /// Creates the message the registration of a device produces.
    pub(crate) fn from_device_addition(
        devpath: String,
        subsystem: String,
        envs: Vec<(String, String)>,
    ) -> Self {
        let uevent = Uevent::new_addition(devpath, subsystem, envs);
        Self::new(uevent, NetlinkSocketAddr::new_unspecified())
    }

    /// Creates a message from the bytes a user-space socket sent to a multicast group.
    pub(crate) fn from_user_bytes(bytes: Vec<u8>, src_addr: NetlinkSocketAddr) -> Result<Self> {
        let uevent = String::from_utf8(bytes)
            .map_err(|_| Error::with_message(Errno::EINVAL, "the uevent is not valid text"))?;
        Ok(Self { uevent, src_addr })
    }

    /// Returns the source address of the uevent message.
    pub(super) fn src_addr(&self) -> &NetlinkSocketAddr {
        &self.src_addr
    }

    /// Writes the uevent to the given `writer`.
    pub(super) fn write_to(&self, writer: &mut dyn MultiWrite) -> Result<()> {
        let _nbytes = writer.write(&mut VmReader::from(self.uevent.as_bytes()))?;
        // `_nbytes` may be smaller than the message size. We ignore it to truncate the message.

        Ok(())
    }
}

impl QueueableMessage for UeventMessage {
    fn total_len(&self) -> usize {
        self.uevent.len()
    }
}

impl MulticastMessage for UeventMessage {}
