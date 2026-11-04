// SPDX-License-Identifier: MPL-2.0

//! This module defines the message segment,
//! which is the basic unit of a netlink message.
//!
//! Typically, a segment will consist of three parts:
//!
//! 1. Header: The headers of all segments are of type [`CMsgSegHdr`],
//!    which indicate the type and total length of the segment.
//!
//! 2. Body: The body is the main component of a segment.
//!    Each segment will have one and only one body.
//!    The body type is defined by the `type_` field of the header.
//!
//! 3. Attributes: Attributes are optional.
//!    A segment can have zero or multiple attributes.
//!    Attributes belong to different classes,
//!    with the class defined by the `type_` field of the header.
//!    The total number of attributes is controlled by the `len` field of the header.
//!
//! Note that all headers, bodies, and attributes require
//! their starting address in memory to be aligned to [`NLMSG_ALIGN`]
//! when copying to and from user space.
//! Therefore, necessary padding must be added to ensure alignment.
//!
//! The layout of a segment in memory is shown below:
//!
//! ┌────────┬─────────┬──────┬─────────┬──────┬──────┬──────┐
//! │ Header │ Padding │ Body │ Padding │ Attr │ Attr │ Attr │
//! └────────┴─────────┴──────┴─────────┴──────┴──────┴──────┘
//!
//! [`NLMSG_ALIGN`]: crate::net::socket::netlink::message::NLMSG_ALIGN

pub(crate) mod addr;
mod legacy;
pub(crate) mod link;
pub(crate) mod route;
pub(crate) mod rule;

use addr::AddrSegment;
use addr::CIfaddrMsg;
use link::LinkSegment;
use route::{CRtMsg, RouteSegment};
use rule::{CFibRuleHdr, RuleSegment};

use crate::{
    net::socket::netlink::message::{
        CMsgSegHdr, CSegmentType, ContinueRead, DoneSegment, ErrorSegment, ProtocolSegment,
    },
    prelude::*,
    util::{MultiRead, MultiWrite},
};

/// The netlink route segment, which is the basic unit of a netlink route message.
#[derive(Clone, Debug)]
pub(crate) enum RtnlSegment {
    NewLink(LinkSegment),
    GetLink(LinkSegment),
    NewAddr(AddrSegment),
    GetAddr(AddrSegment),
    DelAddr(AddrSegment),
    NewRoute(RouteSegment),
    GetRoute(RouteSegment),
    DelRoute(RouteSegment),
    NewRule(RuleSegment),
    GetRule(RuleSegment),
    DelRule(RuleSegment),
    Done(DoneSegment),
    Error(ErrorSegment),
}

impl ProtocolSegment for RtnlSegment {
    fn header(&self) -> &CMsgSegHdr {
        match self {
            RtnlSegment::NewLink(link_segment) | RtnlSegment::GetLink(link_segment) => {
                link_segment.header()
            }
            RtnlSegment::NewAddr(addr_segment)
            | RtnlSegment::GetAddr(addr_segment)
            | RtnlSegment::DelAddr(addr_segment) => addr_segment.header(),
            RtnlSegment::NewRoute(route_segment)
            | RtnlSegment::GetRoute(route_segment)
            | RtnlSegment::DelRoute(route_segment) => route_segment.header(),
            RtnlSegment::NewRule(rule_segment) | RtnlSegment::GetRule(rule_segment) | RtnlSegment::DelRule(rule_segment) => {
                rule_segment.header()
            }
            RtnlSegment::Done(done_segment) => done_segment.header(),
            RtnlSegment::Error(error_segment) => error_segment.header(),
        }
    }

    fn header_mut(&mut self) -> &mut CMsgSegHdr {
        match self {
            RtnlSegment::NewLink(link_segment) | RtnlSegment::GetLink(link_segment) => {
                link_segment.header_mut()
            }
            RtnlSegment::NewAddr(addr_segment)
            | RtnlSegment::GetAddr(addr_segment)
            | RtnlSegment::DelAddr(addr_segment) => addr_segment.header_mut(),
            RtnlSegment::NewRoute(route_segment)
            | RtnlSegment::GetRoute(route_segment)
            | RtnlSegment::DelRoute(route_segment) => route_segment.header_mut(),
            RtnlSegment::NewRule(rule_segment) | RtnlSegment::GetRule(rule_segment) | RtnlSegment::DelRule(rule_segment) => {
                rule_segment.header_mut()
            }
            RtnlSegment::Done(done_segment) => done_segment.header_mut(),
            RtnlSegment::Error(error_segment) => error_segment.header_mut(),
        }
    }

    fn read_from(reader: &mut dyn MultiRead) -> Result<ContinueRead<Self, ErrorSegment>> {
        let header = reader
            .read_val_opt::<CMsgSegHdr>()?
            .ok_or_else(|| Error::with_message(Errno::EINVAL, "the reader length is too small"))?;

        // Only a request that reads data may have the shorter legacy body. A request that changes
        // state needs the full body, as Linux validates it against the full body size.
        let required_body_len = match CSegmentType::try_from(header.type_) {
            Ok(CSegmentType::NEWADDR | CSegmentType::DELADDR) => size_of::<CIfaddrMsg>(),
            Ok(CSegmentType::NEWROUTE | CSegmentType::DELROUTE) => size_of::<CRtMsg>(),
            Ok(CSegmentType::NEWRULE | CSegmentType::DELRULE) => size_of::<CFibRuleHdr>(),
            _ => 0,
        };
        let body_too_small =
            (header.len as usize) < size_of::<CMsgSegHdr>() + required_body_len;

        let segment = match CSegmentType::try_from(header.type_) {
            _ if body_too_small => {
                let payload_len = header.calc_payload_len_with_padding(reader)?;
                reader.skip_some(payload_len);
                ContinueRead::skipped_with_error(
                    Errno::EINVAL,
                    "the message body is too small",
                )
            }
            Ok(CSegmentType::GETLINK) => {
                LinkSegment::read_from(&header, reader)?.map(RtnlSegment::GetLink)
            }
            Ok(CSegmentType::GETADDR) => {
                AddrSegment::read_from(&header, reader)?.map(RtnlSegment::GetAddr)
            }
            Ok(CSegmentType::NEWADDR) => {
                AddrSegment::read_from(&header, reader)?.map(RtnlSegment::NewAddr)
            }
            Ok(CSegmentType::DELADDR) => {
                AddrSegment::read_from(&header, reader)?.map(RtnlSegment::DelAddr)
            }
            Ok(CSegmentType::GETROUTE) => {
                RouteSegment::read_from(&header, reader)?.map(RtnlSegment::GetRoute)
            }
            Ok(CSegmentType::NEWROUTE) => {
                RouteSegment::read_from(&header, reader)?.map(RtnlSegment::NewRoute)
            }
            Ok(CSegmentType::DELROUTE) => {
                RouteSegment::read_from(&header, reader)?.map(RtnlSegment::DelRoute)
            }
            Ok(CSegmentType::GETRULE) => {
                RuleSegment::read_from_ignoring_attrs(&header, reader)?.map(RtnlSegment::GetRule)
            }
            Ok(CSegmentType::NEWRULE) => {
                RuleSegment::read_from(&header, reader)?.map(RtnlSegment::NewRule)
            }
            Ok(CSegmentType::DELRULE) => {
                RuleSegment::read_from(&header, reader)?.map(RtnlSegment::DelRule)
            }
            _ => {
                let payload_len = header.calc_payload_len_with_padding(reader)?;
                reader.skip_some(payload_len);
                ContinueRead::skipped_with_error(
                    Errno::EOPNOTSUPP,
                    "the segment type is not supported",
                )
            }
        };

        Ok(segment.map_err(|error| ErrorSegment::new_from_request(&header, Some(error))))
    }

    fn write_to(&self, writer: &mut dyn MultiWrite) -> Result<()> {
        match self {
            RtnlSegment::NewLink(link_segment) => link_segment.write_to(writer)?,
            RtnlSegment::NewAddr(addr_segment) | RtnlSegment::DelAddr(addr_segment) => {
                addr_segment.write_to(writer)?
            }
            RtnlSegment::NewRoute(route_segment) | RtnlSegment::DelRoute(route_segment) => {
                route_segment.write_to(writer)?
            }
            RtnlSegment::NewRule(rule_segment) | RtnlSegment::DelRule(rule_segment) => rule_segment.write_to(writer)?,
            RtnlSegment::Done(done_segment) => done_segment.write_to(writer)?,
            RtnlSegment::Error(error_segment) => error_segment.write_to(writer)?,
            RtnlSegment::GetAddr(_)
            | RtnlSegment::GetLink(_)
            | RtnlSegment::GetRoute(_)
            | RtnlSegment::GetRule(_) => {
                unreachable!("kernel should not write get requests to user space");
            }
        }
        Ok(())
    }
}
