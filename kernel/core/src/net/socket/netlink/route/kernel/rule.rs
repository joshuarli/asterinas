// SPDX-License-Identifier: MPL-2.0

//! Handle policy-rule requests.

use super::util::finish_response;
use crate::{
    net::{
        route::{RuleOutcome, RuleRecord, dump_rules},
        socket::netlink::{
            message::{CMsgSegHdr, CSegmentType, GetRequestFlags, SegHdrCommonFlags},
            route::message::{RtnlSegment, RuleAttr, RuleSegment, RuleSegmentBody},
        },
    },
    prelude::*,
    util::net::CSocketAddrFamily,
};

/// `FR_ACT_TO_TBL` in Linux.
const ACTION_TO_TABLE: u8 = 1;

/// `RTPROT_KERNEL` in Linux.
const PROTOCOL_KERNEL: u8 = 2;

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
        .map(|record| RtnlSegment::NewRule(record_to_new_rule(request_segment.header(), record)))
        .collect();

    finish_response(request_segment.header(), true, &mut response_segments);

    Ok(response_segments)
}

fn record_to_new_rule(request_header: &CMsgSegHdr, record: &RuleRecord) -> RuleSegment {
    let header = CMsgSegHdr {
        len: 0,
        type_: CSegmentType::NEWRULE as _,
        flags: SegHdrCommonFlags::empty().bits(),
        seq: request_header.seq,
        pid: request_header.pid,
    };

    let family = if record.is_ipv4 {
        CSocketAddrFamily::AF_INET
    } else {
        CSocketAddrFamily::AF_INET6
    };
    let RuleOutcome::Lookup { table } = record.outcome;

    let body = RuleSegmentBody {
        family: family as u8,
        table: u8::try_from(table).unwrap_or(252),
        action: ACTION_TO_TABLE,
    };

    // Reference: <https://elixir.bootlin.com/linux/v7.1/source/net/core/fib_rules.c>.
    let mut attrs = vec![
        RuleAttr::Table(table),
        RuleAttr::SuppressPrefixLen(NO_SUPPRESSED_PREFIX_LEN),
        RuleAttr::Protocol(PROTOCOL_KERNEL),
    ];
    if record.priority != 0 {
        attrs.push(RuleAttr::Priority(record.priority));
    }

    RuleSegment::new(header, body, attrs)
}
