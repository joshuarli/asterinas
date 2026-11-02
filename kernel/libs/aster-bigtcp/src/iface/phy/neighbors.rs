// SPDX-License-Identifier: MPL-2.0

//! The IPv4 neighbors of an Ethernet interface.
//!
//! A packet for a neighbor whose link-layer address is not known yet waits in a bounded queue
//! while address resolution runs, as it does in Linux, instead of being lost. The queue is sent
//! in order when the neighbor answers and is dropped when no answer comes after the probes.
//!
//! Reference: <https://elixir.bootlin.com/linux/v6.12/source/net/core/neighbour.c>.

use alloc::{
    collections::{BTreeMap, VecDeque},
    vec::Vec,
};

use smoltcp::wire::{EthernetAddress, Ipv4Address};

/// The number of address resolution requests sent before a neighbor counts as unreachable
/// (`mcast_solicit`).
const PROBES: u8 = 3;

/// The time between two address resolution requests in milliseconds (`retrans_time`).
const PROBE_INTERVAL_MS: i64 = 1000;

/// The bytes a neighbor may queue while it is unresolved (`unres_qlen_bytes`).
const QUEUE_LIMIT_BYTES: usize = 212992;

/// The number of unresolved neighbors that may wait at the same time.
const MAX_UNRESOLVED: usize = 128;

/// The packets waiting for one unresolved neighbor.
struct Unresolved<P> {
    queue: VecDeque<(P, usize)>,
    queued_bytes: usize,
    probes_sent: u8,
    next_probe_ms: i64,
}

/// What queueing a packet for an unresolved neighbor requires.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Queued {
    /// The neighbor was unknown: the caller sends the first request now.
    ProbeNow,
    /// Resolution is running already.
    Waiting,
    /// Too many neighbors are unresolved: the packet was dropped.
    Dropped,
}

/// What a neighbor that is due needs.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Due<P> {
    /// Another address resolution request for the neighbor.
    Probe(Ipv4Address),
    /// No answer came: the queued packets are dropped.
    Failed(Ipv4Address, Vec<P>),
}

pub(super) struct Neighbors<P> {
    resolved: BTreeMap<Ipv4Address, EthernetAddress>,
    unresolved: BTreeMap<Ipv4Address, Unresolved<P>>,
}

impl<P> Neighbors<P> {
    pub(super) const fn new() -> Self {
        Self {
            resolved: BTreeMap::new(),
            unresolved: BTreeMap::new(),
        }
    }

    /// Returns the link-layer address of a resolved neighbor.
    pub(super) fn resolved(&self, address: Ipv4Address) -> Option<EthernetAddress> {
        self.resolved.get(&address).copied()
    }

    /// Queues a packet of `len` bytes for an unresolved neighbor.
    ///
    /// When the queue would exceed its limit, the oldest packets are dropped.
    pub(super) fn queue(&mut self, address: Ipv4Address, packet: P, len: usize, now_ms: i64) -> Queued {
        let known = self.unresolved.contains_key(&address);
        if !known && self.unresolved.len() >= MAX_UNRESOLVED {
            return Queued::Dropped;
        }

        let entry = self.unresolved.entry(address).or_insert_with(|| Unresolved {
            queue: VecDeque::new(),
            queued_bytes: 0,
            probes_sent: 1,
            next_probe_ms: now_ms + PROBE_INTERVAL_MS,
        });
        while entry.queued_bytes + len > QUEUE_LIMIT_BYTES
            && let Some((_, dropped_len)) = entry.queue.pop_front()
        {
            entry.queued_bytes -= dropped_len;
        }
        entry.queue.push_back((packet, len));
        entry.queued_bytes += len;

        if known { Queued::Waiting } else { Queued::ProbeNow }
    }

    /// Records the link-layer address of a neighbor and returns the packets that waited for it.
    pub(super) fn learn(&mut self, address: Ipv4Address, ether: EthernetAddress) -> Vec<P> {
        self.resolved.insert(address, ether);
        match self.unresolved.remove(&address) {
            Some(entry) => entry.queue.into_iter().map(|(packet, _)| packet).collect(),
            None => Vec::new(),
        }
    }

    /// Returns the next request to send or failure to report at `now_ms`, if any.
    pub(super) fn due(&mut self, now_ms: i64) -> Option<Due<P>> {
        let address = self
            .unresolved
            .iter()
            .find(|(_, entry)| entry.next_probe_ms <= now_ms)
            .map(|(address, _)| *address)?;
        let entry = self.unresolved.get_mut(&address).unwrap();
        if entry.probes_sent < PROBES {
            entry.probes_sent += 1;
            entry.next_probe_ms += PROBE_INTERVAL_MS;
            return Some(Due::Probe(address));
        }
        let entry = self.unresolved.remove(&address).unwrap();
        Some(Due::Failed(
            address,
            entry.queue.into_iter().map(|(packet, _)| packet).collect(),
        ))
    }

    /// Returns when the next request or failure is due.
    pub(super) fn next_deadline_ms(&self) -> Option<i64> {
        self.unresolved
            .values()
            .map(|entry| entry.next_probe_ms)
            .min()
    }

    /// Forgets every neighbor and drops the packets that wait for one.
    pub(super) fn clear(&mut self) {
        self.resolved.clear();
        self.unresolved.clear();
    }
}

#[cfg(ktest)]
mod test {
    use ostd::prelude::ktest;

    use super::*;

    const SERVER: Ipv4Address = Ipv4Address::new(192, 0, 2, 1);
    const OTHER: Ipv4Address = Ipv4Address::new(192, 0, 2, 2);
    const SERVER_ETHER: EthernetAddress = EthernetAddress([2, 0, 0, 0, 0, 1]);

    #[ktest]
    fn the_first_packet_starts_resolution_and_the_answer_releases_the_queue_in_order() {
        let mut neighbors = Neighbors::new();
        assert_eq!(neighbors.queue(SERVER, 1u32, 100, 0), Queued::ProbeNow);
        assert_eq!(neighbors.queue(SERVER, 2, 100, 10), Queued::Waiting);
        assert_eq!(neighbors.queue(SERVER, 3, 100, 20), Queued::Waiting);
        assert_eq!(neighbors.resolved(SERVER), None);

        assert_eq!(neighbors.learn(SERVER, SERVER_ETHER), [1, 2, 3]);

        assert_eq!(neighbors.resolved(SERVER), Some(SERVER_ETHER));
        assert_eq!(neighbors.next_deadline_ms(), None);
        assert_eq!(neighbors.due(10_000), None);
        assert!(neighbors.learn(SERVER, SERVER_ETHER).is_empty());
    }

    #[ktest]
    fn an_overfull_queue_drops_its_oldest_packets() {
        let mut neighbors = Neighbors::new();
        let packet_len = QUEUE_LIMIT_BYTES / 4;
        for packet in 0..6u32 {
            neighbors.queue(SERVER, packet, packet_len, 0);
        }

        assert_eq!(neighbors.learn(SERVER, SERVER_ETHER), [2, 3, 4, 5]);
    }

    #[ktest]
    fn a_packet_larger_than_the_limit_replaces_the_queue() {
        let mut neighbors = Neighbors::new();
        neighbors.queue(SERVER, 1u32, 100, 0);
        neighbors.queue(SERVER, 2, QUEUE_LIMIT_BYTES + 1, 0);

        assert_eq!(neighbors.learn(SERVER, SERVER_ETHER), [2]);
    }

    #[ktest]
    fn unanswered_requests_are_repeated_and_then_the_queue_is_dropped() {
        let mut neighbors = Neighbors::new();
        neighbors.queue(SERVER, 7u32, 100, 5_000);
        neighbors.queue(SERVER, 8, 100, 5_100);

        assert_eq!(neighbors.next_deadline_ms(), Some(6_000));
        assert_eq!(neighbors.due(5_999), None);
        assert_eq!(neighbors.due(6_000), Some(Due::Probe(SERVER)));
        assert_eq!(neighbors.due(6_000), None);
        assert_eq!(neighbors.next_deadline_ms(), Some(7_000));
        assert_eq!(neighbors.due(7_000), Some(Due::Probe(SERVER)));
        assert_eq!(neighbors.due(7_999), None);
        assert_eq!(neighbors.due(8_000), Some(Due::Failed(SERVER, [7, 8].into())));
        assert_eq!(neighbors.next_deadline_ms(), None);
        assert_eq!(neighbors.resolved(SERVER), None);

        assert_eq!(neighbors.queue(SERVER, 9, 100, 9_000), Queued::ProbeNow);
    }

    #[ktest]
    fn a_late_answer_still_releases_the_packets_that_have_not_failed_yet() {
        let mut neighbors = Neighbors::new();
        neighbors.queue(SERVER, 1u32, 100, 0);
        assert_eq!(neighbors.due(2_000), Some(Due::Probe(SERVER)));
        assert_eq!(neighbors.due(2_000), Some(Due::Probe(SERVER)));

        assert_eq!(neighbors.learn(SERVER, SERVER_ETHER), [1]);
        assert_eq!(neighbors.due(3_000), None);
    }

    #[ktest]
    fn neighbors_resolve_independently_and_clearing_forgets_them() {
        let mut neighbors = Neighbors::new();
        neighbors.queue(SERVER, 1u32, 100, 0);
        assert_eq!(neighbors.queue(OTHER, 2, 100, 500), Queued::ProbeNow);
        assert_eq!(neighbors.learn(OTHER, EthernetAddress([2, 0, 0, 0, 0, 2])), [2]);
        assert_eq!(neighbors.next_deadline_ms(), Some(1_000));

        neighbors.clear();

        assert_eq!(neighbors.resolved(OTHER), None);
        assert_eq!(neighbors.next_deadline_ms(), None);
        assert!(neighbors.learn(SERVER, SERVER_ETHER).is_empty());
    }

    #[ktest]
    fn the_number_of_unresolved_neighbors_is_bounded() {
        let mut neighbors = Neighbors::new();
        for index in 0..MAX_UNRESOLVED {
            let address = Ipv4Address::new(10, 0, (index / 250) as u8, (index % 250) as u8 + 1);
            assert_eq!(neighbors.queue(address, 0u32, 1, 0), Queued::ProbeNow);
        }

        assert_eq!(neighbors.queue(Ipv4Address::new(10, 9, 9, 9), 1, 1, 0), Queued::Dropped);
        assert_eq!(neighbors.queue(Ipv4Address::new(10, 0, 0, 1), 1, 1, 0), Queued::Waiting);
    }
}
