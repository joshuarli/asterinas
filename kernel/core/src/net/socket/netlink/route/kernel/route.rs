// SPDX-License-Identifier: MPL-2.0

//! Handle route-related requests.

use core::net::IpAddr;

use super::util::finish_response;
use crate::{
    net::{
        route::{RouteRecord, dump_routes},
        socket::netlink::{
            message::{CMsgSegHdr, CSegmentType, GetRequestFlags, SegHdrCommonFlags},
            route::message::{RouteAttr, RouteSegment, RouteSegmentBody, RtnlSegment},
        },
    },
    prelude::*,
    util::net::CSocketAddrFamily,
};

pub(super) fn do_get_route(request_segment: &RouteSegment) -> Result<Vec<RtnlSegment>> {
    let flags = GetRequestFlags::from_bits_truncate(request_segment.header().flags);
    if !flags.contains(GetRequestFlags::DUMP) {
        return_errno_with_message!(Errno::EOPNOTSUPP, "GETROUTE only supports dump requests");
    }

    // Linux dumps every family when the requested family has no route handler.
    let requested_family = i32::from(request_segment.body().family);
    let dump_ipv4 = requested_family != CSocketAddrFamily::AF_INET6 as i32;
    let dump_ipv6 = requested_family != CSocketAddrFamily::AF_INET as i32;

    let mut response_segments: Vec<RtnlSegment> = dump_routes(dump_ipv4, dump_ipv6)
        .iter()
        .map(|record| RtnlSegment::NewRoute(record_to_new_route(request_segment.header(), record)))
        .collect();

    finish_response(request_segment.header(), true, &mut response_segments);

    Ok(response_segments)
}

fn record_to_new_route(request_header: &CMsgSegHdr, record: &RouteRecord) -> RouteSegment {
    let header = CMsgSegHdr {
        len: 0,
        type_: CSegmentType::NEWROUTE as _,
        flags: SegHdrCommonFlags::empty().bits(),
        seq: request_header.seq,
        pid: request_header.pid,
    };

    let family = match record.destination {
        IpAddr::V4(_) => CSocketAddrFamily::AF_INET,
        IpAddr::V6(_) => CSocketAddrFamily::AF_INET6,
    };

    let body = RouteSegmentBody {
        family: family as u8,
        dst_len: record.destination_prefix_len,
        src_len: 0,
        tos: 0,
        table: u8::try_from(record.table).unwrap_or(252),
        protocol: record.protocol as u8,
        scope: record.scope as u8,
        type_: record.type_ as u8,
        flags: 0,
    };

    // Linux orders the attributes of a route as
    // `RTA_TABLE`, `RTA_DST`, `RTA_PRIORITY`, `RTA_PREFSRC`, `RTA_GATEWAY`, `RTA_OIF` for IPv4,
    // and `RTA_TABLE`, `RTA_DST`, `RTA_PRIORITY`, `RTA_GATEWAY`, `RTA_OIF`,
    // `RTA_CACHEINFO`, `RTA_PREF` for IPv6.
    // Reference: <https://elixir.bootlin.com/linux/v7.1/source/net/ipv4/fib_semantics.c#L1744>
    // and <https://elixir.bootlin.com/linux/v7.1/source/net/ipv6/route.c#L5800>.
    let mut attrs = vec![RouteAttr::Table(record.table)];
    if record.destination_prefix_len > 0 {
        attrs.push(RouteAttr::Dst(record.destination));
    }
    let is_ipv4 = matches!(record.destination, IpAddr::V4(_));
    if record.priority != 0 || !is_ipv4 {
        attrs.push(RouteAttr::Priority(record.priority));
    }
    if let Some(preferred_source) = record.preferred_source {
        attrs.push(RouteAttr::PrefSrc(preferred_source));
    }
    if let Some(gateway) = record.gateway {
        attrs.push(RouteAttr::Gateway(gateway));
    }
    attrs.push(RouteAttr::Oif(record.iface_index));
    if !is_ipv4 {
        attrs.push(RouteAttr::empty_cache_info());
        attrs.push(RouteAttr::Pref(0));
    }

    RouteSegment::new(header, body, attrs)
}
