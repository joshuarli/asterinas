// SPDX-License-Identifier: MPL-2.0

use core::sync::atomic::{AtomicUsize, Ordering};

use aster_bigtcp::diagnostic::tcp_identity_count;

use crate::net::iface::{iter_all_ifaces, network_registry};

pub(crate) static DATAGRAM_SOCKETS: AtomicUsize = AtomicUsize::new(0);
pub(crate) static RAW_SOCKETS: AtomicUsize = AtomicUsize::new(0);

/// Holds one slot of a live-socket counter.
pub(crate) struct Counted(&'static AtomicUsize);

impl Counted {
    pub(crate) fn new(counter: &'static AtomicUsize) -> Self {
        counter.fetch_add(1, Ordering::Relaxed);
        Self(counter)
    }
}

impl Drop for Counted {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

/// The socket counters `/proc/net/sockstat` and `/proc/net/sockstat6` report.
///
/// Only IP sockets are counted: the kernel keeps no count of unix, netlink or packet sockets.
pub(crate) struct SocketSummary {
    pub(crate) used: usize,
    pub(crate) tcp_in_use_ipv4: usize,
    pub(crate) tcp_in_use_ipv6: usize,
    pub(crate) tcp_orphaned: usize,
    pub(crate) tcp_time_wait: usize,
    pub(crate) tcp_allocated: usize,
    pub(crate) udp_in_use: usize,
    pub(crate) raw_in_use: usize,
    pub(crate) fragment_queues: usize,
    pub(crate) fragment_bytes: usize,
}

pub(crate) fn socket_summary() -> SocketSummary {
    let (mut in_use_ipv4, mut in_use_ipv6, mut time_wait, mut orphaned, mut orphaned_time_wait) = (0, 0, 0, 0, 0);
    let (mut fragment_queues, mut fragment_bytes) = (0, 0);
    for iface in iter_all_ifaces() {
        let counts = iface.common().tcp_counts();
        in_use_ipv4 += counts.in_use_ipv4;
        in_use_ipv6 += counts.in_use_ipv6;
        time_wait += counts.time_wait;
        orphaned += counts.orphaned;
        orphaned_time_wait += counts.orphaned_time_wait;
        let (queues, bytes) = iface.common().ipv4_fragment_queues();
        fragment_queues += queues;
        fragment_bytes += bytes;
    }
    let tcp_allocated = tcp_identity_count().saturating_sub(orphaned_time_wait);
    SocketSummary {
        used: tcp_allocated + DATAGRAM_SOCKETS.load(Ordering::Relaxed) + RAW_SOCKETS.load(Ordering::Relaxed),
        tcp_in_use_ipv4: in_use_ipv4,
        tcp_in_use_ipv6: in_use_ipv6,
        tcp_orphaned: orphaned,
        tcp_time_wait: time_wait,
        tcp_allocated,
        udp_in_use: network_registry().udp_snapshots().len(),
        raw_in_use: RAW_SOCKETS.load(Ordering::Relaxed),
        fragment_queues,
        fragment_bytes,
    }
}
