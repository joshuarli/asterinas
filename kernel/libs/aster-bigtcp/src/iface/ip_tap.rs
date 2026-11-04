// SPDX-License-Identifier: MPL-2.0

use alloc::{sync::Arc, vec::Vec};
use aster_softirq::BottomHalfDisabled;
use ostd::{mm::{Infallible, VmReader, VmWriter}, sync::SpinLock};

/// An observer of structurally valid, reassembled IP packets addressed to this host.
///
/// IPv4 checksum validation follows the receiving device's checksum capabilities. Both methods
/// run while the interface is being polled and must not block or call back into it.
pub trait IpTap: Send + Sync {
    /// Selects the IPv4 protocol to observe.
    fn accepts(&self, protocol: u8) -> bool;
    /// Receives the complete IP datagram while the interface is being polled.
    fn deliver(&self, ifindex: u32, packet: &[u8]);
}

pub(super) struct IpTaps(SpinLock<Vec<Arc<dyn IpTap>>, BottomHalfDisabled>);

impl IpTaps {
    pub(super) fn new() -> Self { Self(SpinLock::new(Vec::new())) }
    pub(super) fn add(&self, tap: Arc<dyn IpTap>) {
        let mut taps = self.0.lock();
        if !taps.iter().any(|existing| Arc::ptr_eq(existing, &tap)) { taps.push(tap); }
    }
    pub(super) fn remove(&self, tap: &Arc<dyn IpTap>) {
        self.0.lock().retain(|existing| !Arc::ptr_eq(existing, tap));
    }
    pub(super) fn deliver(&self, ifindex: u32, protocol: u8, mut reader: VmReader<'_, Infallible>) {
        let taps = self.0.lock();
        if !taps.iter().any(|tap| tap.accepts(protocol)) { return; }
        let mut packet = alloc::vec![0; reader.remain()];
        reader.read(&mut VmWriter::from(packet.as_mut_slice()));
        for tap in taps.iter().filter(|tap| tap.accepts(protocol)) { tap.deliver(ifindex, &packet); }
    }
}

#[cfg(ktest)]
mod test {
    use core::sync::atomic::{AtomicUsize, Ordering};
    use ostd::prelude::ktest;
    use super::*;

    struct Observer(AtomicUsize);
    impl IpTap for Observer {
        fn accepts(&self, protocol: u8) -> bool { protocol == 1 }
        fn deliver(&self, _ifindex: u32, _packet: &[u8]) { self.0.fetch_add(1, Ordering::Relaxed); }
    }

    #[ktest]
    fn removing_ip_observer_stops_delivery() {
        let observer = Arc::new(Observer(AtomicUsize::new(0)));
        let tap: Arc<dyn IpTap> = observer.clone();
        let taps = IpTaps::new();
        taps.add(tap.clone());
        taps.add(tap.clone());
        taps.deliver(1, 17, VmReader::from(&[1u8][..]));
        taps.deliver(1, 1, VmReader::from(&[1u8][..]));
        taps.remove(&tap);
        taps.deliver(1, 1, VmReader::from(&[1u8][..]));
        assert_eq!(observer.0.load(Ordering::Relaxed), 1);
    }
}
