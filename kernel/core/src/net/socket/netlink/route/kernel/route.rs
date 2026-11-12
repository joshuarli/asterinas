// SPDX-License-Identifier: MPL-2.0

//! Handle route-related requests.

use core::net::{IpAddr, Ipv4Addr};

use aster_bigtcp::wire::Ipv4Cidr;

use super::{notify::RequestOrigin, util::finish_response};
use crate::{
    net::{
        iface::config,
        route::{
            Ipv4RouteSelector, NewIpv4Route, NewRouteAction, Rejection, RouteRecord, RouteType,
            dump_routes, Ipv4RouteQuery, Ipv4RouteQueryMode, lookup_ipv4_route,
        },
        socket::{
            netlink::{
                message::{
                    CMsgSegHdr, CSegmentType, GetRequestFlags, NewRequestFlags, SegHdrCommonFlags,
                },
                route::message::{RouteAttr, RouteSegment, RouteSegmentBody, RtnlSegment},
            },
            util::options::check_current_privileged,
        },
    },
    prelude::*,
    process::posix_thread::AsPosixThread,
    util::net::CSocketAddrFamily,
};

pub(super) fn do_get_route(request_segment: &RouteSegment) -> Result<Vec<RtnlSegment>> {
    let flags = GetRequestFlags::from_bits_truncate(request_segment.header().flags);
    if !flags.contains(GetRequestFlags::DUMP) {
        return do_lookup_route(request_segment);
    }

    // Linux dumps every family when the requested family has no route handler.
    let requested_family = i32::from(request_segment.body().family);
    let dump_ipv4 = requested_family != CSocketAddrFamily::AF_INET6 as i32;
    let dump_ipv6 = requested_family != CSocketAddrFamily::AF_INET as i32;

    let mut response_segments: Vec<RtnlSegment> = dump_routes(dump_ipv4, dump_ipv6)
        .iter()
        .map(|record| {
            RtnlSegment::NewRoute(record_to_route(
                request_segment.header(),
                CSegmentType::NEWROUTE,
                record,
            ))
        })
        .collect();

    finish_response(request_segment.header(), true, &mut response_segments);

    Ok(response_segments)
}

const RTM_F_CLONED: u32 = 0x200;
const RTM_F_LOOKUP_TABLE: u32 = 0x1000;
const RTM_F_FIB_MATCH: u32 = 0x2000;

fn do_lookup_route(request: &RouteSegment) -> Result<Vec<RtnlSegment>> {
    let body = request.body();
    if body.family != CSocketAddrFamily::AF_INET as u8 {
        return_errno_with_message!(Errno::EOPNOTSUPP, "only IPv4 route queries are supported");
    }
    let mut query = Ipv4RouteQuery { mode: if body.flags & RTM_F_FIB_MATCH != 0 { Ipv4RouteQueryMode::FibMatch } else { Ipv4RouteQueryMode::Output }, destination: Ipv4Addr::UNSPECIFIED, source: None, device: None, mark: 0 };
    let current = current_thread!();
    let mut uid = Some(u32::from(current.as_posix_thread().unwrap().credentials().fsuid()));
    for attr in request.attrs() {
        match attr {
            RouteAttr::Dst(IpAddr::V4(address)) => query.destination = *address,
            RouteAttr::Src(IpAddr::V4(address)) => query.source = Some(*address).filter(|address| !address.is_unspecified()),
            RouteAttr::Oif(index) => query.device = Some(*index).filter(|index| *index != 0),
            RouteAttr::Mark(mark) => query.mark = *mark,
            RouteAttr::Uid(value) => uid = Some(*value).filter(|value| *value != u32::MAX),
            RouteAttr::Dst(IpAddr::V6(_)) | RouteAttr::Src(IpAddr::V6(_)) => {
                return_errno_with_message!(Errno::EINVAL, "the route query attribute is invalid");
            }
            RouteAttr::Iif(index) if *index != 0 => {
                return_errno_with_message!(Errno::EOPNOTSUPP, "input route queries are not supported");
            }
            _ => {}
        }
    }
    let (record, source) = lookup_ipv4_route(&query)?;
    let response = if body.flags & RTM_F_FIB_MATCH != 0 {
        record_to_route(request.header(), CSegmentType::NEWROUTE, &record)
    } else {
        let output_index = record.iface_index.unwrap();
        let output_is_loopback = crate::net::iface::iter_all_ifaces()
            .any(|iface| iface.index() == output_index && iface.type_() == aster_bigtcp::iface::InterfaceType::LOOPBACK);
        let flags = RTM_F_CLONED | match record.type_ {
            RouteType::Broadcast => 0x9000_0000,
            RouteType::Multicast => 0x2000_0000,
            RouteType::Local => 0x8000_0000,
            _ if output_is_loopback => 0x8000_0000,
            _ => 0,
        };
        let table = if body.flags & RTM_F_LOOKUP_TABLE != 0 { record.table } else { 254 };
        let mut attrs = vec![RouteAttr::Table(table), RouteAttr::Dst(IpAddr::V4(query.destination))];
        if let Some(source) = query.source {
            attrs.push(RouteAttr::Src(IpAddr::V4(source)));
        }
        attrs.push(RouteAttr::Oif(output_index));
        if query.source.is_none() && let Some(source) = source {
            attrs.push(RouteAttr::PrefSrc(IpAddr::V4(source)));
        }
        if !output_is_loopback && let Some(gateway) = record.gateway {
            attrs.push(RouteAttr::Gateway(gateway));
        }
        if query.mark != 0 { attrs.push(RouteAttr::Mark(query.mark)); }
        if let Some(uid) = uid { attrs.push(RouteAttr::Uid(uid)); }
        attrs.push(RouteAttr::empty_cache_info());
        let body = RouteSegmentBody {
            family: CSocketAddrFamily::AF_INET as u8,
            dst_len: 32, src_len: if query.source.is_some() { 32 } else { 0 }, tos: body.tos,
            table: u8::try_from(table).unwrap_or(252), protocol: 0, scope: 0,
            type_: record.type_ as u8, flags,
        };
        RouteSegment::new(CMsgSegHdr { len: 0, type_: CSegmentType::NEWROUTE as _, flags: 0, seq: request.header().seq, pid: request.header().pid }, body, attrs)
    };
    let mut segments = vec![RtnlSegment::NewRoute(response)];
    segments.extend(super::acknowledgement(request.header()));
    Ok(segments)
}

/// `RT_SCOPE_HOST` in Linux.
const SCOPE_HOST: u8 = 254;

/// `RT_SCOPE_NOWHERE` in Linux.
const SCOPE_NOWHERE: u8 = 255;

/// Returns what a new route of a type does, after the checks that Linux makes before it looks
/// for an existing route.
///
/// Reference: <https://elixir.bootlin.com/linux/v7.1/source/net/ipv4/fib_semantics.c> (`fib_props`
/// and `fib_create_info`).
fn new_route_action(type_: u8, scope: u8, parsed: &ParsedRoute) -> Result<NewRouteAction> {
    if scope < widest_scope(type_) {
        return_errno_with_message!(Errno::EINVAL, "the route type or its scope is invalid");
    }

    let rejection = match type_ {
        6 => Rejection::Blackhole,
        7 => Rejection::Unreachable,
        8 => Rejection::Prohibit,
        9 => Rejection::Throw,
        1..=5 => {
            if scope > SCOPE_HOST {
                return_errno_with_message!(Errno::EINVAL, "the route scope is invalid");
            }
            if parsed.gateway.is_some() && scope == SCOPE_HOST {
                return_errno_with_message!(Errno::EINVAL, "a host route cannot have a gateway");
            }
            if type_ != 1 && parsed.iface_index.is_none() && parsed.gateway.is_none() {
                return_errno_with_message!(Errno::ENODEV, "the route type needs a device");
            }
            let type_ = match type_ {
                1 => RouteType::Unicast,
                2 => RouteType::Local,
                3 => RouteType::Broadcast,
                4 => RouteType::Anycast,
                5 => RouteType::Multicast,
                _ => unreachable!(),
            };
            return Ok(NewRouteAction::Send(type_));
        }
        _ => return_errno_with_message!(Errno::EINVAL, "the route type is invalid"),
    };
    Ok(NewRouteAction::Reject(rejection))
}

/// Returns the widest scope a route of a type can have; `RT_SCOPE_NOWHERE` for the types that
/// Linux refuses.
fn widest_scope(type_: u8) -> u8 {
    match type_ {
        2 => SCOPE_HOST,
        3 | 4 => 253,
        1 | 5..=9 => 0,
        _ => SCOPE_NOWHERE,
    }
}

pub(super) fn do_new_route(request_segment: &RouteSegment) -> Result<()> {
    check_current_privileged()?;

    let body = request_segment.body();
    let parsed = ParsedRoute::from_request(request_segment)?;

    let request_flags = NewRequestFlags::from_bits_truncate(request_segment.header().flags);
    if request_flags.intersects(NewRequestFlags::REPLACE | NewRequestFlags::APPEND) {
        return_errno_with_message!(
            Errno::EOPNOTSUPP,
            "replacing or appending a route is not supported"
        );
    }
    let action = new_route_action(body.type_, body.scope, &parsed)?;

    config::add_ipv4_route(
        NewIpv4Route {
            action,
            table: parsed.table,
            destination: parsed.destination,
            gateway: parsed.gateway,
            iface_index: parsed.iface_index,
            priority: parsed.priority.unwrap_or(0),
            protocol: body.protocol,
            scope: body.scope,
        },
        RequestOrigin::request(request_segment.header()),
    )
}

pub(super) fn do_del_route(request_segment: &RouteSegment) -> Result<()> {
    check_current_privileged()?;

    let body = request_segment.body();
    let parsed = ParsedRoute::from_request(request_segment)?;

    config::remove_ipv4_route(
        &Ipv4RouteSelector {
            table: parsed.table,
            destination: parsed.destination,
            priority: parsed.priority.filter(|priority| *priority != 0),
            gateway: parsed.gateway,
            iface_index: parsed.iface_index,
            protocol: Some(body.protocol).filter(|protocol| *protocol != 0),
            type_: Some(body.type_).filter(|type_| *type_ != 0),
            scope: Some(body.scope).filter(|scope| *scope != SCOPE_NOWHERE),
        },
        RequestOrigin::request(request_segment.header()),
    )
}

/// The parts of a route request that both installing and removing a route use.
struct ParsedRoute {
    table: u32,
    destination: Ipv4Cidr,
    gateway: Option<Ipv4Addr>,
    iface_index: Option<u32>,
    priority: Option<u32>,
}

impl ParsedRoute {
    fn from_request(request_segment: &RouteSegment) -> Result<Self> {
        let body = request_segment.body();
        if body.family != CSocketAddrFamily::AF_INET as u8 {
            return_errno_with_message!(Errno::EOPNOTSUPP, "only IPv4 routes can be changed");
        }
        if body.dst_len > 32 {
            return_errno_with_message!(Errno::EINVAL, "the prefix length is invalid");
        }
        if body.src_len != 0 || body.flags != 0 {
            return_errno_with_message!(
                Errno::EOPNOTSUPP,
                "source-specific routes and route flags are not supported"
            );
        }
        if body.tos != 0 {
            return_errno_with_message!(Errno::EOPNOTSUPP, "routes with a TOS are not supported");
        }

        let mut table = u32::from(body.table);
        let mut destination = None;
        let mut gateway = None;
        let mut iface_index = None;
        let mut priority = None;
        for attr in request_segment.attrs() {
            match attr {
                RouteAttr::Table(id) => table = *id,
                RouteAttr::Dst(IpAddr::V4(address)) => destination = Some(*address),
                RouteAttr::Gateway(IpAddr::V4(address)) => gateway = Some(*address),
                RouteAttr::Dst(IpAddr::V6(_)) | RouteAttr::Gateway(IpAddr::V6(_)) => {
                    return_errno_with_message!(Errno::EINVAL, "the address is not IPv4");
                }
                RouteAttr::Oif(index) => iface_index = Some(*index).filter(|index| *index != 0),
                RouteAttr::Priority(value) => priority = Some(*value),
                RouteAttr::Pref(_) => {}
                RouteAttr::PrefSrc(_) | RouteAttr::CacheInfo(_) | RouteAttr::Src(_)
                | RouteAttr::Iif(_) | RouteAttr::Mark(_) | RouteAttr::Uid(_) => {
                    return_errno_with_message!(
                        Errno::EOPNOTSUPP,
                        "the route attribute is not supported"
                    );
                }
            }
        }

        let destination = match destination {
            Some(address) => address,
            None if body.dst_len == 0 => Ipv4Addr::UNSPECIFIED,
            None => return_errno_with_message!(Errno::EINVAL, "the route has no destination"),
        };

        Ok(Self {
            table,
            destination: Ipv4Cidr::new(destination, body.dst_len),
            gateway,
            iface_index,
            priority,
        })
    }
}

pub(super) fn record_to_route(
    request_header: &CMsgSegHdr,
    type_: CSegmentType,
    record: &RouteRecord,
) -> RouteSegment {
    let header = CMsgSegHdr {
        len: 0,
        type_: type_ as _,
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
        protocol: record.protocol.get(),
        scope: record.scope.get(),
        type_: record.type_ as u8,
        flags: 0,
    };

    // Linux orders the attributes of a route as
    // `RTA_TABLE`, `RTA_DST`, `RTA_PRIORITY`, `RTA_PREFSRC`, `RTA_GATEWAY`, `RTA_OIF` for IPv4,
    // and `RTA_TABLE`, `RTA_DST`, `RTA_PRIORITY`, `RTA_GATEWAY`, `RTA_OIF`,
    // `RTA_CACHEINFO`, `RTA_PREF` for IPv6.
    // Reference: <https://elixir.bootlin.com/linux/v7.1/source/net/ipv4/fib_semantics.c>
    // and <https://elixir.bootlin.com/linux/v7.1/source/net/ipv6/route.c>.
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
    if let Some(iface_index) = record.iface_index {
        attrs.push(RouteAttr::Oif(iface_index));
    }
    if !is_ipv4 {
        attrs.push(RouteAttr::empty_cache_info());
        attrs.push(RouteAttr::Pref(0));
    }

    RouteSegment::new(header, body, attrs)
}
