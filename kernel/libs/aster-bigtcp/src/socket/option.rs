// SPDX-License-Identifier: MPL-2.0

use smoltcp::time::Duration;

use super::{NeedIfacePoll, unbound::RawTcpSocket};

/// A trait defines setting socket options on a raw socket.
pub trait RawTcpSetOption {
    /// Returns the socket mark used for route selection.
    fn mark(&self) -> u32;

    /// Reports whether a connected socket has a cached output route.
    fn route_valid(&self) -> bool;

    /// Changes the socket mark used for route selection.
    fn set_mark(&self, mark: u32);

    /// Sets the keep alive interval.
    ///
    /// Polling the iface _may_ be required after this method succeeds.
    fn set_keep_alive(&self, interval: Option<Duration>) -> NeedIfacePoll;

    /// Enables or disables Nagle’s Algorithm.
    ///
    /// Polling the iface is _not_ required after this method succeeds.
    fn set_nagle_enabled(&self, enabled: bool);
}

/// Socket options on a raw socket.
pub struct RawTcpOption {
    /// The socket mark used for route selection.
    pub mark: u32,
    /// The keep alive interval.
    pub keep_alive: Option<Duration>,
    /// Whether Nagle's algorithm is enabled.
    pub is_nagle_enabled: bool,
}

impl RawTcpOption {
    pub(super) fn apply(&self, socket: &mut RawTcpSocket) {
        socket.set_keep_alive(self.keep_alive);
        socket.set_nagle_enabled(self.is_nagle_enabled);
    }

    pub(super) fn inherit(from: &RawTcpSocket, to: &mut RawTcpSocket) {
        to.set_keep_alive(from.keep_alive());
        to.set_nagle_enabled(from.nagle_enabled());
    }
}
