// SPDX-License-Identifier: MPL-2.0

use super::{RawSocketOption, SocketOption, impl_raw_sock_option_get_only, impl_raw_socket_option};
use crate::{
    net::socket::packet::options::{IgnoreOutgoing, Statistics},
    prelude::*,
};

/// Socket options for packet sockets.
///
/// Reference: <https://elixir.bootlin.com/linux/v6.0.9/source/include/uapi/linux/if_packet.h#L48>.
#[expect(non_camel_case_types)]
#[expect(clippy::upper_case_acronyms)]
#[repr(i32)]
#[derive(Clone, Copy, Debug, TryFromInt)]
pub(crate) enum CPacketOptionName {
    STATISTICS = 6,
    IGNORE_OUTGOING = 23,
}

pub(crate) fn new_packet_option(name: i32) -> Result<Box<dyn RawSocketOption>> {
    let name = CPacketOptionName::try_from(name).map_err(|_| Errno::ENOPROTOOPT)?;
    match name {
        CPacketOptionName::STATISTICS => Ok(Box::new(Statistics::new())),
        CPacketOptionName::IGNORE_OUTGOING => Ok(Box::new(IgnoreOutgoing::new())),
    }
}

impl_raw_sock_option_get_only!(Statistics);
impl_raw_socket_option!(IgnoreOutgoing);
