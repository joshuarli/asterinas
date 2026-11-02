// SPDX-License-Identifier: MPL-2.0

use aster_bigtcp::iface::{FrameDirection, FrameKind, LinkFrame, LinkTap};
use aster_softirq::BottomHalfDisabled;

use super::{ETH_P_ALL, PACKET_DEFAULT_BUF_SIZE, PacketSocketAddr, PacketType, options::PacketStatistics};
use crate::{events::IoEvents, prelude::*, process::signal::Pollee};

/// The selection and the receive queue of a packet socket.
///
/// An interface calls the tap while it polls, so everything here is safe to use with bottom halves
/// disabled.
pub(super) struct PacketTap {
    pollee: Pollee,
    state: SpinLock<TapState, BottomHalfDisabled>,
}

struct TapState {
    protocol: u16,
    ifindex: i32,
    running: bool,
    error: Option<Errno>,
    queue: VecDeque<ReceivedFrame>,
    queued_bytes: usize,
    capacity: usize,
    ignore_outgoing: bool,
    statistics: PacketStatistics,
}

struct ReceivedFrame {
    bytes: Vec<u8>,
    ifindex: u32,
    hardware_type: u16,
    packet_type: PacketType,
    ethertype: u16,
}

/// A frame taken out of the receive queue.
pub(super) struct DequeuedFrame {
    bytes: Vec<u8>,
    addr: PacketSocketAddr,
}

impl DequeuedFrame {
    pub(super) fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub(super) fn addr(&self) -> PacketSocketAddr {
        self.addr
    }
}

impl ReceivedFrame {
    fn addr(&self) -> PacketSocketAddr {
        let mut link_addr = [0u8; super::MAX_LINK_ADDR_LEN];
        link_addr[..6].copy_from_slice(&self.bytes[6..12]);
        PacketSocketAddr::new(
            self.ethertype,
            self.ifindex as i32,
            self.hardware_type,
            self.packet_type as u8,
            6,
            link_addr,
        )
        .with_full_length()
    }
}

impl PacketTap {
    pub(super) fn new(pollee: Pollee, protocol: u16) -> Arc<Self> {
        Arc::new(Self {
            pollee,
            state: SpinLock::new(TapState {
                protocol,
                ifindex: 0,
                running: protocol != 0,
                error: None,
                queue: VecDeque::new(),
                queued_bytes: 0,
                capacity: PACKET_DEFAULT_BUF_SIZE,
                ignore_outgoing: false,
                statistics: PacketStatistics::default(),
            }),
        })
    }

    pub(super) fn protocol(&self) -> u16 {
        self.state.lock().protocol
    }

    pub(super) fn ifindex(&self) -> i32 {
        self.state.lock().ifindex
    }

    /// Selects a protocol and an interface the way a Linux packet socket rebinds.
    ///
    /// A change of either drops the selection first. It then receives again unless the interface
    /// is down, in which case the next receive fails with `ENETDOWN`.
    pub(super) fn rebind(&self, protocol: u16, ifindex: i32, iface_is_up: bool) {
        let mut state = self.state.lock();
        let changed = state.protocol != protocol || state.ifindex != ifindex;
        if !changed {
            return;
        }

        state.running = false;
        state.protocol = protocol;
        state.ifindex = ifindex;
        if protocol == 0 {
            return;
        }
        if ifindex == 0 || iface_is_up {
            state.running = true;
        } else {
            state.error = Some(Errno::ENETDOWN);
            drop(state);
            self.pollee.notify(IoEvents::ERR);
        }
    }

    /// Sets the number of frame bytes that the receive queue holds before it drops frames.
    pub(super) fn set_capacity(&self, capacity: usize) {
        self.state.lock().capacity = capacity;
    }

    pub(super) fn ignore_outgoing(&self) -> bool {
        self.state.lock().ignore_outgoing
    }

    pub(super) fn set_ignore_outgoing(&self, ignore: bool) {
        self.state.lock().ignore_outgoing = ignore;
    }

    /// Reports the counters and starts them again, like `PACKET_STATISTICS`.
    pub(super) fn take_statistics(&self) -> PacketStatistics {
        let mut state = self.state.lock();
        let statistics = core::mem::take(&mut state.statistics);
        PacketStatistics {
            packets: statistics.packets.wrapping_add(statistics.drops),
            drops: statistics.drops,
        }
    }

    /// Takes the pending error, like reading `SO_ERROR`.
    pub(super) fn take_error(&self) -> Option<Errno> {
        let error = self.state.lock().error.take();
        self.pollee.invalidate();
        error
    }

    /// Takes the next frame, or the pending error, from the receive queue.
    pub(super) fn dequeue(&self, consume: bool) -> Result<DequeuedFrame> {
        let mut state = self.state.lock();
        if let Some(errno) = state.error.take() {
            return Err(Error::with_message(errno, "the packet socket has a pending error"));
        }

        if consume {
            let Some(frame) = state.queue.pop_front() else {
                return_errno_with_message!(Errno::EAGAIN, "the receive queue is empty");
            };
            state.queued_bytes -= frame.bytes.len();
            let addr = frame.addr();
            Ok(DequeuedFrame {
                bytes: frame.bytes,
                addr,
            })
        } else {
            let Some(frame) = state.queue.front() else {
                return_errno_with_message!(Errno::EAGAIN, "the receive queue is empty");
            };
            Ok(DequeuedFrame {
                bytes: frame.bytes.clone(),
                addr: frame.addr(),
            })
        }
    }

    pub(super) fn io_events(&self) -> IoEvents {
        let state = self.state.lock();
        let mut events = IoEvents::OUT;
        if !state.queue.is_empty() {
            events |= IoEvents::IN;
        }
        if state.error.is_some() {
            events |= IoEvents::ERR;
        }
        events
    }
}

impl LinkTap for PacketTap {
    fn accepts(&self, direction: FrameDirection, ethertype: u16) -> bool {
        let state = self.state.lock();
        state.running
            && match direction {
                FrameDirection::Incoming => state.protocol == ETH_P_ALL || state.protocol == ethertype,
                FrameDirection::Outgoing => state.protocol == ETH_P_ALL && !state.ignore_outgoing,
            }
    }

    fn deliver(&self, frame: &LinkFrame<'_>) {
        let mut state = self.state.lock();
        if state.ifindex != 0 && state.ifindex as u32 != frame.iface_index {
            return;
        }
        if state.queued_bytes + frame.bytes.len() > state.capacity {
            state.statistics.drops = state.statistics.drops.wrapping_add(1);
            return;
        }
        state.statistics.packets = state.statistics.packets.wrapping_add(1);

        let packet_type = match frame.kind {
            FrameKind::Host => PacketType::Host,
            FrameKind::Broadcast => PacketType::Broadcast,
            FrameKind::Multicast => PacketType::Multicast,
            FrameKind::OtherHost => PacketType::OtherHost,
            FrameKind::Outgoing => PacketType::Outgoing,
        };
        state.queued_bytes += frame.bytes.len();
        state.queue.push_back(ReceivedFrame {
            bytes: frame.bytes.to_vec(),
            ifindex: frame.iface_index,
            hardware_type: frame.iface_type as u16,
            packet_type,
            ethertype: frame.ethertype,
        });
        drop(state);

        self.pollee.notify(IoEvents::IN);
    }

    fn link_changed(&self, iface_index: u32, up: bool) {
        let mut state = self.state.lock();
        if state.ifindex as u32 != iface_index || state.ifindex == 0 {
            return;
        }

        if up {
            if state.protocol != 0 {
                state.running = true;
            }
            return;
        }
        if !state.running {
            return;
        }
        state.running = false;
        state.error = Some(Errno::ENETDOWN);
        drop(state);

        self.pollee.notify(IoEvents::ERR);
    }
}
