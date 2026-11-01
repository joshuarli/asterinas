// SPDX-License-Identifier: MPL-2.0

use super::sched::PollScheduler;
use crate::net::socket::ip::{DatagramObserver, StreamObserver};

pub(in crate::net) struct BigtcpExt;

impl aster_bigtcp::ext::Ext for BigtcpExt {
    type ScheduleNextPoll = PollScheduler;

    type TcpEventObserver = StreamObserver;
    type UdpEventObserver = DatagramObserver;

    fn wall_time_ns() -> u64 {
        aster_time::read_wall_time().as_nanos() as u64
    }
}
