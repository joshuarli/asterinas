// SPDX-License-Identifier: MPL-2.0

use alloc::{sync::Arc, vec::Vec};

use aster_softirq::BottomHalfDisabled;
use ostd::{mm::{Infallible, VmReader}, sync::SpinLock};

use super::{InterfaceType, common::PollPhy};

/// The direction of a frame relative to an interface.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FrameDirection {
    /// The frame arrives from the network.
    Incoming,
    /// The frame leaves for the network.
    Outgoing,
}

/// The kind of a frame, as seen by a link-layer tap.
///
/// Reference: <https://elixir.bootlin.com/linux/v6.0.9/source/include/uapi/linux/if_packet.h#L26>.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FrameKind {
    /// Addressed to the interface.
    Host,
    /// Addressed to the broadcast address.
    Broadcast,
    /// Addressed to a multicast address.
    Multicast,
    /// Addressed to another host.
    OtherHost,
    /// Sent by this host.
    Outgoing,
}

/// A link-layer frame handed to a [`LinkTap`].
///
/// The bytes always start with an Ethernet header. An interface without link-layer framing
/// gets a header with zero addresses.
#[derive(Debug)]
pub struct LinkFrame<'a> {
    pub iface_index: u32,
    pub iface_type: InterfaceType,
    pub kind: FrameKind,
    pub ethertype: u16,
    pub bytes: &'a [u8],
}

/// An observer of the link-layer frames of an interface.
pub trait LinkTap: Send + Sync {
    /// Returns whether the tap wants frames of the direction and EtherType.
    fn accepts(&self, direction: FrameDirection, ethertype: u16) -> bool;

    /// Delivers a frame.
    ///
    /// This runs while the interface is being polled, so it must neither sleep nor call back
    /// into the interface.
    fn deliver(&self, frame: &LinkFrame<'_>);

    /// Reports that the interface has been brought up or down.
    fn link_changed(&self, iface_index: u32, up: bool);
}

/// The link-layer taps registered on an interface.
pub(super) struct LinkTaps {
    iface_index: u32,
    iface_type: InterfaceType,
    taps: SpinLock<Vec<Arc<dyn LinkTap>>, BottomHalfDisabled>,
}

impl LinkTaps {
    pub(super) fn new(iface_index: u32, iface_type: InterfaceType) -> Self {
        Self {
            iface_index,
            iface_type,
            taps: SpinLock::new(Vec::new()),
        }
    }

    pub(super) fn add(&self, tap: Arc<dyn LinkTap>) {
        let mut taps = self.taps.lock();
        if !taps.iter().any(|existing| Arc::ptr_eq(existing, &tap)) {
            taps.push(tap);
        }
    }

    pub(super) fn remove(&self, tap: &Arc<dyn LinkTap>) {
        self.taps.lock().retain(|existing| !Arc::ptr_eq(existing, tap));
    }

    pub(super) fn link_changed(&self, up: bool) {
        for tap in self.taps.lock().iter() {
            tap.link_changed(self.iface_index, up);
        }
    }

    pub(super) fn deliver<'a>(
        &self,
        phy: &dyn PollPhy,
        direction: FrameDirection,
        origin: Option<&Arc<dyn LinkTap>>,
        reader: impl Fn() -> VmReader<'a, Infallible>,
    ) {
        let taps = self.taps.lock();
        if taps.is_empty() {
            return;
        }
        let Some(ethertype) = phy.peek_ethertype(reader()) else {
            return;
        };

        let mut bytes: Option<Vec<u8>> = None;
        for tap in taps.iter() {
            if origin.is_some_and(|origin| Arc::ptr_eq(origin, tap)) {
                continue;
            }
            if !tap.accepts(direction, ethertype) {
                continue;
            }
            let bytes = bytes.get_or_insert_with(|| phy.copy_ethernet_frame(reader()));
            let kind = match direction {
                FrameDirection::Outgoing => FrameKind::Outgoing,
                FrameDirection::Incoming => frame_kind(bytes, &phy.hardware_addr()),
            };
            tap.deliver(&LinkFrame {
                iface_index: self.iface_index,
                iface_type: self.iface_type,
                kind,
                ethertype,
                bytes,
            });
        }
    }
}

fn frame_kind(frame: &[u8], own_addr: &[u8; 6]) -> FrameKind {
    let destination = &frame[..6];
    if destination == [0xff; 6] {
        FrameKind::Broadcast
    } else if destination[0] & 1 != 0 {
        FrameKind::Multicast
    } else if destination == own_addr {
        FrameKind::Host
    } else {
        FrameKind::OtherHost
    }
}
