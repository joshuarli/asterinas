// SPDX-License-Identifier: MPL-2.0

use crate::{
    net::socket::netlink::message::{Attribute, CAttrHeader, ContinueRead},
    prelude::*,
    util::MultiRead,
};

/// Policy-rule attributes.
///
/// Reference: <https://elixir.bootlin.com/linux/v7.1/source/include/uapi/linux/fib_rules.h>.
#[expect(non_camel_case_types)]
#[expect(clippy::upper_case_acronyms)]
#[repr(u16)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, TryFromInt)]
enum RuleAttrClass {
    UNSPEC = 0,
    DST = 1,
    SRC = 2,
    IIFNAME = 3,
    GOTO = 4,
    UNUSED2 = 5,
    PRIORITY = 6,
    UNUSED3 = 7,
    UNUSED4 = 8,
    UNUSED5 = 9,
    FWMARK = 10,
    FLOW = 11,
    TUN_ID = 12,
    SUPPRESS_IFGROUP = 13,
    SUPPRESS_PREFIXLEN = 14,
    TABLE = 15,
    FWMASK = 16,
    OIFNAME = 17,
    PAD = 18,
    L3MDEV = 19,
    UID_RANGE = 20,
    PROTOCOL = 21,
}

#[derive(Clone, Debug)]
pub(crate) enum RuleAttr {
    Table(u32),
    SuppressPrefixLen(u32),
    Protocol(u8),
    Priority(u32),
}

impl RuleAttr {
    fn class(&self) -> RuleAttrClass {
        match self {
            RuleAttr::Table(_) => RuleAttrClass::TABLE,
            RuleAttr::SuppressPrefixLen(_) => RuleAttrClass::SUPPRESS_PREFIXLEN,
            RuleAttr::Protocol(_) => RuleAttrClass::PROTOCOL,
            RuleAttr::Priority(_) => RuleAttrClass::PRIORITY,
        }
    }
}

impl Attribute for RuleAttr {
    fn type_(&self) -> u16 {
        self.class() as u16
    }

    fn payload_as_bytes(&self) -> &[u8] {
        match self {
            RuleAttr::Table(value)
            | RuleAttr::SuppressPrefixLen(value)
            | RuleAttr::Priority(value) => value.as_bytes(),
            RuleAttr::Protocol(value) => value.as_bytes(),
        }
    }

    fn read_from(header: &CAttrHeader, reader: &mut dyn MultiRead) -> Result<ContinueRead<Self>>
    where
        Self: Sized,
    {
        reader.skip_some(header.payload_len());

        // Only dump requests are served, and Linux ignores their attributes.

        Ok(ContinueRead::Skipped)
    }

    fn read_all_from(
        reader: &mut dyn MultiRead,
        total_len: usize,
    ) -> Result<ContinueRead<Vec<Self>>>
    where
        Self: Sized,
    {
        reader.skip_some(total_len);

        Ok(ContinueRead::Skipped)
    }
}
