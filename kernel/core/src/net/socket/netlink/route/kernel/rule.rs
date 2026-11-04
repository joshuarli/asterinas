// SPDX-License-Identifier: MPL-2.0

//! Handle policy-rule requests.

use super::{notify::RequestOrigin, util::finish_response};
use crate::{
    net::{
        iface::config,
        route::{Ipv4RuleRequest, MarkSelector, RuleOutcome, RuleRecord, dump_rules},
        socket::netlink::{
            message::{CMsgSegHdr, CSegmentType, GetRequestFlags, NewRequestFlags, SegHdrCommonFlags},
            route::message::{RtnlSegment, RuleAttr, RuleSegment, RuleSegmentBody},
        },
    },
    prelude::*,
    net::socket::util::options::check_current_privileged,
    util::net::CSocketAddrFamily,
};

/// `FR_ACT_TO_TBL` in Linux.
const ACTION_TO_TABLE: u8 = 1;

/// Linux reports a rule with no prefix-length suppression as all ones.
const NO_SUPPRESSED_PREFIX_LEN: u32 = u32::MAX;

pub(super) fn do_get_rule(request_segment: &RuleSegment) -> Result<Vec<RtnlSegment>> {
    let flags = GetRequestFlags::from_bits_truncate(request_segment.header().flags);
    if !flags.contains(GetRequestFlags::DUMP) {
        return_errno_with_message!(Errno::EOPNOTSUPP, "GETRULE only supports dump requests");
    }

    let requested_family = i32::from(request_segment.body().family);
    let dump_ipv4 = requested_family != CSocketAddrFamily::AF_INET6 as i32;
    let dump_ipv6 = requested_family != CSocketAddrFamily::AF_INET as i32;

    let mut response_segments: Vec<RtnlSegment> = dump_rules(dump_ipv4, dump_ipv6)
        .iter()
        .map(|record| RtnlSegment::NewRule(record_to_rule(request_segment.header(), CSegmentType::NEWRULE, record)))
        .collect();

    finish_response(request_segment.header(), true, &mut response_segments);

    Ok(response_segments)
}

pub(super) fn do_new_rule(segment: &RuleSegment) -> Result<()> {
    check_current_privileged()?;
    let flags = NewRequestFlags::from_bits_truncate(segment.header().flags);
    if flags.intersects(NewRequestFlags::REPLACE | NewRequestFlags::APPEND) {
        return_errno_with_message!(Errno::EOPNOTSUPP, "rule replacement and append are unsupported");
    }
    config::add_ipv4_rule(parse_rule(segment, false)?, flags.contains(NewRequestFlags::EXCL), RequestOrigin::request(segment.header()))
}

pub(super) fn do_del_rule(segment: &RuleSegment) -> Result<()> {
    check_current_privileged()?;
    config::remove_ipv4_rule(parse_rule(segment, true)?, RequestOrigin::request(segment.header()))
}

fn parse_rule(segment: &RuleSegment, deleting: bool) -> Result<Ipv4RuleRequest> {
    let body = segment.body();
    if body.family != CSocketAddrFamily::AF_INET as u8 {
        return_errno_with_message!(Errno::EAFNOSUPPORT, "only IPv4 policy rules can be changed");
    }
    if body.dst_len != 0 || body.src_len != 0 || body.tos != 0 || body.flags != 0 || body.res1 != 0 || body.res2 != 0 {
        return_errno_with_message!(Errno::EOPNOTSUPP, "the policy rule selector is unsupported");
    }
    let mut priority = None;
    let mut table = u32::from(body.table);
    let mut mark = None;
    let mut mask = None;
    let mut protocol = None;
    for attr in segment.attrs() {
        match attr {
            RuleAttr::Priority(value) => priority = Some(*value),
            RuleAttr::Table(value) => table = *value,
            RuleAttr::Mark(value) => mark = Some(*value),
            RuleAttr::Mask(value) => mask = Some(*value),
            RuleAttr::Protocol(value) => protocol = Some(*value),
            RuleAttr::SuppressPrefixLen(value) if *value == u32::MAX => (),
            RuleAttr::Invalid(_) => return_errno_with_message!(Errno::EINVAL, "invalid rule attribute"),
            _ => return_errno_with_message!(Errno::EOPNOTSUPP, "the policy rule attribute is unsupported"),
        }
    }
    let outcome = match body.action {
        0 if deleting => None,
        1 if table != 0 => Some(RuleOutcome::Lookup { table }),
        1 => return_errno_with_message!(Errno::EOPNOTSUPP, "automatic rule tables are unsupported"),
        6 => Some(RuleOutcome::Blackhole),
        7 => Some(RuleOutcome::Unreachable),
        8 => Some(RuleOutcome::Prohibit),
        _ => return_errno_with_message!(Errno::EOPNOTSUPP, "the policy rule action is unsupported"),
    };
    let value = mark.unwrap_or(0);
    let mask = mask.unwrap_or(if value == 0 { 0 } else { u32::MAX });
    let mark = if value != 0 || mask != 0 { Some(MarkSelector { value, mask }) } else { None };
    if table != 0 && outcome.is_some_and(|outcome| !matches!(outcome, RuleOutcome::Lookup { .. })) {
        return_errno_with_message!(Errno::EOPNOTSUPP, "a table is unsupported for this rule action");
    }
    let table = (table != 0 && outcome.is_none()).then_some(table);
    let protocol = if deleting { protocol.filter(|value| *value != 0) } else { protocol };
    Ok(Ipv4RuleRequest { priority, outcome, table, mark, protocol })
}

pub(super) fn record_to_rule(request_header: &CMsgSegHdr, type_: CSegmentType, record: &RuleRecord) -> RuleSegment {
    let header = CMsgSegHdr {
        len: 0,
        type_: type_ as _,
        flags: SegHdrCommonFlags::empty().bits(),
        seq: request_header.seq,
        pid: request_header.pid,
    };

    let family = if record.is_ipv4 {
        CSocketAddrFamily::AF_INET
    } else {
        CSocketAddrFamily::AF_INET6
    };
    let (table, action) = match record.outcome {
        RuleOutcome::Lookup { table } => (table, ACTION_TO_TABLE),
        RuleOutcome::Unreachable => (0, 7),
        RuleOutcome::Prohibit => (0, 8),
        RuleOutcome::Blackhole => (0, 6),
    };

    let body = RuleSegmentBody {
        family: family as u8,
        table: u8::try_from(table).unwrap_or(252),
        action,
        ..Default::default()
    };

    // Reference: <https://elixir.bootlin.com/linux/v7.1/source/net/core/fib_rules.c>.
    let mut attrs = vec![
        RuleAttr::Table(table),
        RuleAttr::SuppressPrefixLen(NO_SUPPRESSED_PREFIX_LEN),
        RuleAttr::Protocol(record.protocol),
    ];
    if let Some(selector) = record.mark {
        if selector.value != 0 { attrs.push(RuleAttr::Mark(selector.value)); }
        if selector.mask != 0 || selector.value != 0 { attrs.push(RuleAttr::Mask(selector.mask)); }
    }
    if record.priority != 0 {
        attrs.push(RuleAttr::Priority(record.priority));
    }

    RuleSegment::new(header, body, attrs)
}
