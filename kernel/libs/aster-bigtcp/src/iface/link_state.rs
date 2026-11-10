// SPDX-License-Identifier: MPL-2.0

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

use super::{InterfaceFlags, InterfaceType};

/// Whether a link has a carrier, and how many times it gained and lost one.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Carrier {
    pub on: bool,
    pub up_count: u32,
    pub down_count: u32,
}

impl Carrier {
    /// Returns the number of carrier transitions, as `IFLA_CARRIER_CHANGES` reports it.
    pub fn changes(&self) -> u32 {
        self.up_count.wrapping_add(self.down_count)
    }
}

/// The frames and bytes that an interface received and transmitted.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct LinkCounters {
    pub rx_packets: u64,
    pub tx_packets: u64,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
}

/// The carrier and the frame counters of an interface.
pub(super) struct LinkState {
    carrier_follows_admin: bool,
    carrier: AtomicBool,
    carrier_up_count: AtomicU32,
    carrier_down_count: AtomicU32,
    rx_packets: AtomicU64,
    tx_packets: AtomicU64,
    rx_bytes: AtomicU64,
    tx_bytes: AtomicU64,
}

impl LinkState {
    /// Creates the state of a new interface.
    ///
    /// A loopback interface always has a carrier. Other interfaces have one exactly while they
    /// are up, as a Linux virtio-net device does since Linux 6.11. Such an interface starts
    /// down, and Linux counts the carrier loss when it registers the device.
    pub(super) fn new(type_: InterfaceType, flags: InterfaceFlags) -> Self {
        let carrier_follows_admin = type_ != InterfaceType::LOOPBACK;
        let on = !carrier_follows_admin || flags.contains(InterfaceFlags::UP);
        Self {
            carrier_follows_admin,
            carrier: AtomicBool::new(on),
            carrier_up_count: AtomicU32::new(u32::from(carrier_follows_admin && on)),
            carrier_down_count: AtomicU32::new(u32::from(carrier_follows_admin)),
            rx_packets: AtomicU64::new(0),
            tx_packets: AtomicU64::new(0),
            rx_bytes: AtomicU64::new(0),
            tx_bytes: AtomicU64::new(0),
        }
    }

    /// Records that the interface was brought up or down.
    pub(super) fn admin_changed(&self, up: bool) {
        if !self.carrier_follows_admin || self.carrier.swap(up, Ordering::Relaxed) == up {
            return;
        }
        let count = if up {
            &self.carrier_up_count
        } else {
            &self.carrier_down_count
        };
        count.fetch_add(1, Ordering::Relaxed);
    }

    pub(super) fn carrier(&self) -> Carrier {
        Carrier {
            on: self.carrier.load(Ordering::Relaxed),
            up_count: self.carrier_up_count.load(Ordering::Relaxed),
            down_count: self.carrier_down_count.load(Ordering::Relaxed),
        }
    }

    pub(super) fn record_rx(&self, frame_len: usize) {
        self.rx_packets.fetch_add(1, Ordering::Relaxed);
        self.rx_bytes.fetch_add(frame_len as u64, Ordering::Relaxed);
    }

    pub(super) fn record_tx(&self, frame_len: usize) {
        self.tx_packets.fetch_add(1, Ordering::Relaxed);
        self.tx_bytes.fetch_add(frame_len as u64, Ordering::Relaxed);
    }

    pub(super) fn counters(&self) -> LinkCounters {
        LinkCounters {
            rx_packets: self.rx_packets.load(Ordering::Relaxed),
            tx_packets: self.tx_packets.load(Ordering::Relaxed),
            rx_bytes: self.rx_bytes.load(Ordering::Relaxed),
            tx_bytes: self.tx_bytes.load(Ordering::Relaxed),
        }
    }
}

#[cfg(ktest)]
mod test {
    use ostd::prelude::ktest;

    use super::*;

    #[ktest]
    fn an_ethernet_carrier_starts_lost_and_follows_each_admin_transition() {
        let state = LinkState::new(InterfaceType::ETHER, InterfaceFlags::BROADCAST);
        assert_eq!(
            state.carrier(),
            Carrier { on: false, up_count: 0, down_count: 1 }
        );

        state.admin_changed(true);
        state.admin_changed(true);
        assert_eq!(
            state.carrier(),
            Carrier { on: true, up_count: 1, down_count: 1 }
        );

        state.admin_changed(false);
        assert_eq!(
            state.carrier(),
            Carrier { on: false, up_count: 1, down_count: 2 }
        );
        assert_eq!(state.carrier().changes(), 3);
    }

    #[ktest]
    fn a_loopback_carrier_never_changes() {
        let state = LinkState::new(InterfaceType::LOOPBACK, InterfaceFlags::UP);
        state.admin_changed(false);
        state.admin_changed(true);
        assert_eq!(
            state.carrier(),
            Carrier { on: true, up_count: 0, down_count: 0 }
        );
    }

    #[ktest]
    fn frames_count_in_their_own_direction() {
        let state = LinkState::new(InterfaceType::ETHER, InterfaceFlags::BROADCAST);
        state.record_rx(60);
        state.record_tx(42);
        state.record_tx(100);
        assert_eq!(
            state.counters(),
            LinkCounters { rx_packets: 1, tx_packets: 2, rx_bytes: 60, tx_bytes: 142 }
        );
    }
}
