// SPDX-License-Identifier: MPL-2.0

use alloc::sync::Arc;
use aster_bigtcp::iface::ScheduleNextPoll;

use super::{iter_all_ifaces, sched::PollScheduler};
use crate::net::socket::ip::{DatagramObserver, StreamObserver};

pub(in crate::net) struct BigtcpExt;

impl aster_bigtcp::ext::Ext for BigtcpExt {
    type ScheduleNextPoll = PollScheduler;

    type TcpEventObserver = StreamObserver;
    type UdpEventObserver = DatagramObserver;

    fn wake_forwarded_ip(ifindex: u32) {
        if let Some(iface) = iter_all_ifaces().find(|iface| iface.index() == ifindex) {
            let now = ostd::timer::Jiffies::elapsed().as_duration().as_millis() as u64;
            iface.sched_poll().schedule_next_poll(Some(now.max(1)));
        }
    }

    fn ip_route(destination: aster_bigtcp::wire::IpAddress, mark: u32) -> Option<core::result::Result<(Arc<super::Iface>, aster_bigtcp::socket::IpNextHop, aster_bigtcp::iface::PathMtuRoute), ()>> {
        match destination {
            aster_bigtcp::wire::IpAddress::Ipv4(dst) => Some(crate::net::route::lookup_ipv4_poll_route(dst, mark).map_err(|_| ())),
            _ => None,
        }
    }

    fn wall_time_ns() -> u64 {
        aster_time::read_wall_time().as_nanos() as u64
    }
}
