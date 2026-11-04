// SPDX-License-Identifier: MPL-2.0

use crate::{iface::ScheduleNextPoll, socket::SocketEventObserver};

/// Extension to be implemented by users of this crate.
///
/// This should be implemented on an empty type that carries no data, since the type will never
/// actually be instantiated.
///
/// The purpose of having this trait is to allow users of this crate to inject multiple types
/// without the hassle of writing multiple trait bounds, which can be achieved by using the types
/// associated with this trait.
pub trait Ext: 'static {
    /// The type for ifaces to schedule the next poll.
    type ScheduleNextPoll: ScheduleNextPoll;

    /// The type for TCP sockets to observe events.
    type TcpEventObserver: SocketEventObserver + Clone;

    /// The type for UDP sockets to observe events.
    type UdpEventObserver: SocketEventObserver;

    /// Returns the current wall-clock time in nanoseconds since the Unix epoch.
    ///
    /// UDP sockets stamp each received and transmitted packet with it.
    fn wall_time_ns() -> u64;

    /// Schedules processing of an IP packet forwarded to an interface.
    fn wake_forwarded_ip(_ifindex: u32) {}
}
