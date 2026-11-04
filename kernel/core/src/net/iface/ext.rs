// SPDX-License-Identifier: MPL-2.0

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

    fn wall_time_ns() -> u64 {
        aster_time::read_wall_time().as_nanos() as u64
    }
}
