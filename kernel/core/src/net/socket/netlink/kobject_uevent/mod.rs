// SPDX-License-Identifier: MPL-2.0

pub(super) use message::UeventMessage;

use crate::{
    net::socket::netlink::{
        GroupIdSet,
        common::NetlinkSocket,
        table::{NetlinkUeventProtocol, SupportedNetlinkProtocol},
    },
    prelude::*,
};

mod bound;
mod message;

pub(crate) type NetlinkUeventSocket = NetlinkSocket<NetlinkUeventProtocol>;

const KERNEL_UEVENT_GROUPS: u32 = 1;

/// Delivers the uevent a write of `command` to a device's `uevent` attribute asks for
/// to every socket listening for kernel uevents.
pub(crate) fn broadcast_synthetic_uevent(
    command: &str,
    devpath: String,
    subsystem: String,
    envs: Vec<(String, String)>,
) -> Result<()> {
    let message = UeventMessage::from_synthetic_command(command, devpath, subsystem, envs)?;
    NetlinkUeventProtocol::multicast(GroupIdSet::new(KERNEL_UEVENT_GROUPS), message)
}
