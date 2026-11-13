// SPDX-License-Identifier: MPL-2.0

mod common;
#[expect(clippy::module_inception)]
mod iface;
mod ip_tap;
mod link_state;
mod packet_slice;
mod phy;
mod poll;
mod poll_iface;
mod port;
mod sched;
mod tap;
mod time;
mod network_registry;
mod wire;

const IFNAMESIZE: usize = 16;
pub type InterfaceName = aster_util::fixed_str::FixedCStr<IFNAMESIZE>;

pub use common::{BoundPort, BoundTcpPort, IfaceCommon, InterfaceFlags, InterfaceType};
pub(crate) use common::UdpFailure;
pub use iface::{Iface, PathMtu, PathMtuRoute};
pub use ip_tap::IpTap;
pub use link_state::{Carrier, LinkCounters};
pub(crate) use packet_slice::PacketSlice;
pub use phy::{EtherIface, IpIface};
pub(crate) use poll_iface::{PollKey, PollableIfaceMut};
pub use port::BindPortConfig;
pub use sched::ScheduleNextPoll;
pub use network_registry::{NetworkRegistry, UdpReservation};
pub use tap::{FrameDirection, FrameKind, LinkFrame, LinkTap};
