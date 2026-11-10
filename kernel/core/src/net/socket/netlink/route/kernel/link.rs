// SPDX-License-Identifier: MPL-2.0

//! Handle link-related requests.

use core::num::NonZero;

use aster_bigtcp::{
    iface::{InterfaceFlags, InterfaceType},
    wire::EthernetAddress,
};

use super::util::finish_response;
use crate::{
    net::{
        iface::{DEFAULT_TX_QUEUE_LEN, Iface, config, iter_all_ifaces},
        socket::{
            netlink::{
                message::{
                    CMsgSegHdr, CSegmentType, GetRequestFlags, NewRequestFlags, SegHdrCommonFlags,
                },
                route::message::{
                    CLinkStats64, LinkAttr, LinkSegment, LinkSegmentBody, OperState, RtExtFilter,
                    RtnlSegment,
                },
            },
            util::options::check_current_privileged,
        },
    },
    prelude::*,
    util::net::CSocketAddrFamily,
};

/// The unspecified link-layer address.
const UNSPECIFIED_LINK_ADDR: EthernetAddress = EthernetAddress([0; 6]);

pub(super) fn do_get_link(request_segment: &LinkSegment) -> Result<Vec<RtnlSegment>> {
    let filter_by = FilterBy::from_request(request_segment)?;
    let stats = if skips_stats(request_segment) {
        LinkStats::Skipped
    } else {
        LinkStats::Included
    };

    let mut response_segments: Vec<RtnlSegment> = iter_all_ifaces()
        // Filter to include only requested links.
        .filter(|iface| match &filter_by {
            FilterBy::Index(index) => *index == iface.index(),
            FilterBy::Name(name) => *name == iface.name().as_cstr(),
            FilterBy::Dump => true,
        })
        .map(|iface| iface_to_new_link(request_segment.header(), iface, 0, stats))
        .map(RtnlSegment::NewLink)
        .collect();

    let dump_all = matches!(filter_by, FilterBy::Dump);

    if !dump_all && response_segments.is_empty() {
        return_errno_with_message!(Errno::ENODEV, "no link found");
    }

    finish_response(request_segment.header(), dump_all, &mut response_segments);

    Ok(response_segments)
}

/// Changes an existing link, as `do_setlink` does for `RTM_NEWLINK`.
///
/// Only bringing a link up or down applies. A request to change the name, the hardware address,
/// the MTU, the queue length or the link mode fails before anything changes.
///
/// Reference: `rtnl_newlink` in <https://elixir.bootlin.com/linux/v7.1/source/net/core/rtnetlink.c>.
pub(super) fn do_new_link(request_segment: &LinkSegment) -> Result<()> {
    check_current_privileged()?;

    let body = request_segment.body();
    let attrs = request_segment.attrs();
    let name = attrs.iter().find_map(|attr| match attr {
        LinkAttr::Name(name) => Some(name),
        _ => None,
    });
    let index = body
        .index
        .filter(|index| i32::try_from(index.get()).is_ok());
    let iface = match (index, name) {
        (Some(index), _) => iter_all_ifaces().find(|iface| iface.index() == index.get()),
        (None, Some(name)) => iter_all_ifaces().find(|iface| iface.name().as_cstr() == name.as_cstr()),
        (None, None) => None,
    };

    let request_flags = NewRequestFlags::from_bits_truncate(request_segment.header().flags);
    let Some(iface) = iface else {
        if request_flags.contains(NewRequestFlags::CREATE) {
            return_errno_with_message!(Errno::EOPNOTSUPP, "creating a link is not supported");
        }
        return_errno_with_message!(Errno::ENODEV, "no link found");
    };
    if request_flags.contains(NewRequestFlags::EXCL) {
        return_errno_with_message!(Errno::EEXIST, "the link already exists");
    }
    if request_flags.contains(NewRequestFlags::REPLACE) {
        return_errno_with_message!(Errno::EOPNOTSUPP, "replacing a link is not supported");
    }

    for attr in attrs {
        let unchanged = match attr {
            LinkAttr::Name(name) => name.as_cstr() == iface.name().as_cstr(),
            LinkAttr::Address(address) => {
                *address == iface.ethernet_addr().unwrap_or(UNSPECIFIED_LINK_ADDR)
            }
            LinkAttr::Mtu(mtu) => *mtu as usize == iface.mtu(),
            LinkAttr::TxqLen(len) => *len == DEFAULT_TX_QUEUE_LEN,
            LinkAttr::LinkMode(mode) => *mode == 0,
            _ => true,
        };
        if !unchanged {
            return_errno_with_message!(
                Errno::EOPNOTSUPP,
                "only the up flag of a link can be changed"
            );
        }
    }

    if body.flags.is_empty() && body.change == 0 {
        return Ok(());
    }
    let requested = if body.change == 0 {
        body.flags
    } else {
        let change = InterfaceFlags::from_bits_truncate(body.change);
        (body.flags & change) | (iface.flags() - change)
    };
    config::change_flags(iface, requested)
}

/// Whether a link message carries the link's counters.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum LinkStats {
    Included,
    Skipped,
}

fn skips_stats(request_segment: &LinkSegment) -> bool {
    request_segment.attrs().iter().any(|attr| {
        matches!(attr, LinkAttr::ExtMask(filter) if filter.contains(RtExtFilter::SKIP_STATS))
    })
}

enum FilterBy<'a> {
    Index(u32),
    Name(&'a CStr),
    Dump,
}

impl<'a> FilterBy<'a> {
    fn from_request(request_segment: &'a LinkSegment) -> Result<Self> {
        let dump_all = {
            let flags = GetRequestFlags::from_bits_truncate(request_segment.header().flags);
            flags.contains(GetRequestFlags::DUMP)
        };
        if dump_all {
            validate_dumplink_request(request_segment.body())?;
            return Ok(Self::Dump);
        }

        validate_getlink_request(request_segment.body())?;

        // `index` takes precedence over `required_name`.

        if let Some(required_index) = request_segment.body().index {
            return Ok(Self::Index(required_index.get()));
        }

        let required_name = request_segment.attrs().iter().find_map(|attr| {
            if let LinkAttr::Name(name) = attr {
                Some(name.as_cstr())
            } else {
                None
            }
        });
        if let Some(required_name) = required_name {
            return Ok(Self::Name(required_name));
        }

        return_errno_with_message!(
            Errno::EINVAL,
            "either interface name or index should be specified for non-dump mode"
        );
    }
}

// The below functions starting with `validate_` should only be enabled in strict mode.
// Reference: <https://docs.kernel.org/userspace-api/netlink/intro.html#strict-checking>.

fn validate_getlink_request(body: &LinkSegmentBody) -> Result<()> {
    // FIXME: The Linux implementation also checks the `padding` and `change` fields,
    // but these fields are lost during the conversion of a `CIfInfoMsg` to `LinkSegmentBody`.
    // We should consider including the `change` field in `LinkSegmentBody`.
    // Reference: <https://elixir.bootlin.com/linux/v6.13/source/net/core/rtnetlink.c#L4043>.
    if !body.flags.is_empty() || body.type_ != InterfaceType::NETROM {
        return_errno_with_message!(Errno::EINVAL, "the flags or the type is not valid");
    }

    Ok(())
}

fn validate_dumplink_request(body: &LinkSegmentBody) -> Result<()> {
    // FIXME: The Linux implementation also checks the `padding` and `change` fields.
    // Reference: <https://elixir.bootlin.com/linux/v6.13/source/net/core/rtnetlink.c#L2378>.
    if !body.flags.is_empty() || body.type_ != InterfaceType::NETROM {
        return_errno_with_message!(Errno::EINVAL, "the flags or the type is not valid");
    }

    // The check is from <https://elixir.bootlin.com/linux/v6.13/source/net/core/rtnetlink.c#L2383>.
    if body.index.is_some() {
        return_errno_with_message!(
            Errno::EINVAL,
            "filtering by interface index is not valid for link dumps"
        );
    }

    Ok(())
}

/// Linux reports a loopback interface as `UNKNOWN` while it is up, as it has no carrier to track.
fn oper_state(iface: &Arc<Iface>) -> OperState {
    if !iface.flags().contains(InterfaceFlags::UP) {
        OperState::Down
    } else if iface.type_() == InterfaceType::LOOPBACK {
        OperState::Unknown
    } else {
        OperState::Up
    }
}

pub(super) fn iface_to_new_link(
    request_header: &CMsgSegHdr,
    iface: &Arc<Iface>,
    change: u32,
    stats: LinkStats,
) -> LinkSegment {
    let header = CMsgSegHdr {
        len: 0,
        type_: CSegmentType::NEWLINK as _,
        flags: SegHdrCommonFlags::empty().bits(),
        seq: request_header.seq,
        pid: request_header.pid,
    };

    let link_message = LinkSegmentBody {
        family: CSocketAddrFamily::AF_UNSPEC,
        type_: iface.type_(),
        index: NonZero::new(iface.index()),
        flags: iface.flags(),
        change,
    };

    // Linux may report dozens of attributes in a fixed order.
    // See the reference below for the complete attribute list and ordering.
    // TODO: Asterinas currently reports only a subset of these attributes.
    // Reference: <https://elixir.bootlin.com/linux/v7.1/source/net/core/rtnetlink.c#L2050>.
    let carrier = iface.carrier();
    let mut attrs = Vec::with_capacity(12);
    attrs.extend([
        LinkAttr::Name(*iface.name()),
        LinkAttr::TxqLen(DEFAULT_TX_QUEUE_LEN),
        LinkAttr::OperState(oper_state(iface)),
        LinkAttr::Mtu(iface.mtu() as u32),
        LinkAttr::Carrier(u8::from(carrier.on)),
        LinkAttr::CarrierChanges(carrier.changes()),
        LinkAttr::CarrierUpCount(carrier.up_count),
        LinkAttr::CarrierDownCount(carrier.down_count),
    ]);

    let (link_addr, link_broadcast_addr) = match iface.ethernet_addr() {
        Some(ethernet_addr) => (ethernet_addr, EthernetAddress::BROADCAST),
        None => (UNSPECIFIED_LINK_ADDR, UNSPECIFIED_LINK_ADDR),
    };
    attrs.extend([
        LinkAttr::Address(link_addr),
        LinkAttr::Broadcast(link_broadcast_addr),
    ]);

    if stats == LinkStats::Included {
        let counters = iface.link_counters();
        let stats = CLinkStats64 {
            rx_packets: counters.rx_packets,
            tx_packets: counters.tx_packets,
            rx_bytes: counters.rx_bytes,
            tx_bytes: counters.tx_bytes,
            ..CLinkStats64::default()
        };
        attrs.extend([LinkAttr::Stats64(stats), LinkAttr::Stats(stats.truncated())]);
    }

    LinkSegment::new(header, link_message, attrs)
}
