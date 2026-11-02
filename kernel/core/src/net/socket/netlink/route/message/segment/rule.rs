// SPDX-License-Identifier: MPL-2.0

use super::legacy::CRtGenMsg;
use crate::{
    net::socket::netlink::{
        message::{SegmentBody, SegmentCommon},
        route::message::attr::rule::RuleAttr,
    },
    prelude::*,
};

pub(crate) type RuleSegment = SegmentCommon<RuleSegmentBody, RuleAttr>;

impl SegmentBody for RuleSegmentBody {
    type CLegacyType = CRtGenMsg;
    type CType = CFibRuleHdr;
}

/// `fib_rule_hdr` in Linux.
///
/// Reference: <https://elixir.bootlin.com/linux/v7.1/source/include/uapi/linux/fib_rules.h#L16>.
#[repr(C)]
#[derive(Clone, Copy, Debug, Pod)]
pub(crate) struct CFibRuleHdr {
    pub family: u8,
    pub dst_len: u8,
    pub src_len: u8,
    pub tos: u8,
    pub table: u8,
    pub res1: u8,
    pub res2: u8,
    pub action: u8,
    pub flags: u32,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct RuleSegmentBody {
    pub family: u8,
    pub table: u8,
    pub action: u8,
}

impl TryFrom<CFibRuleHdr> for RuleSegmentBody {
    type Error = Error;

    fn try_from(value: CFibRuleHdr) -> Result<Self> {
        Ok(Self {
            family: value.family,
            table: value.table,
            action: value.action,
        })
    }
}

impl From<RuleSegmentBody> for CFibRuleHdr {
    fn from(value: RuleSegmentBody) -> Self {
        Self {
            family: value.family,
            dst_len: 0,
            src_len: 0,
            tos: 0,
            table: value.table,
            res1: 0,
            res2: 0,
            action: value.action,
            flags: 0,
        }
    }
}

impl From<CRtGenMsg> for CFibRuleHdr {
    fn from(value: CRtGenMsg) -> Self {
        Self {
            family: value.family,
            dst_len: 0,
            src_len: 0,
            tos: 0,
            table: 0,
            res1: 0,
            res2: 0,
            action: 0,
            flags: 0,
        }
    }
}
