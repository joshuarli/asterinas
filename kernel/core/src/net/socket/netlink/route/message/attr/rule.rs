// SPDX-License-Identifier: MPL-2.0

use crate::{
    net::socket::netlink::message::{Attribute, CAttrHeader, ContinueRead},
    prelude::*,
    util::MultiRead,
};

#[derive(Clone, Debug)]
pub(crate) enum RuleAttr {
    Table(u32),
    SuppressPrefixLen(u32),
    Protocol(u8),
    Priority(u32),
    Mark(u32),
    Mask(u32),
    Unsupported(u16),
    Invalid(u16),
}

impl Attribute for RuleAttr {
    fn type_(&self) -> u16 {
        match self {
            Self::Priority(_) => 6,
            Self::Mark(_) => 10,
            Self::SuppressPrefixLen(_) => 14,
            Self::Table(_) => 15,
            Self::Mask(_) => 16,
            Self::Protocol(_) => 21,
            Self::Unsupported(kind) | Self::Invalid(kind) => *kind,
        }
    }

    fn payload_as_bytes(&self) -> &[u8] {
        match self {
            Self::Table(value) | Self::SuppressPrefixLen(value) | Self::Priority(value)
            | Self::Mark(value) | Self::Mask(value) => value.as_bytes(),
            Self::Protocol(value) => value.as_bytes(),
            Self::Unsupported(_) | Self::Invalid(_) => &[],
        }
    }

    fn read_from(header: &CAttrHeader, reader: &mut dyn MultiRead) -> Result<ContinueRead<Self>> {
        let kind = header.type_();
        let len = header.payload_len();
        let value = match (kind, len) {
            (6, 4) => Self::Priority(reader.read_val_opt::<u32>()?.unwrap()),
            (10, 4) => Self::Mark(reader.read_val_opt::<u32>()?.unwrap()),
            (14, 4) => Self::SuppressPrefixLen(reader.read_val_opt::<u32>()?.unwrap()),
            (15, 4) => Self::Table(reader.read_val_opt::<u32>()?.unwrap()),
            (16, 4) => Self::Mask(reader.read_val_opt::<u32>()?.unwrap()),
            (21, 1) => Self::Protocol(reader.read_val_opt::<u8>()?.unwrap()),
            (6 | 10 | 14 | 15 | 16 | 21, _) => { reader.skip_some(len); Self::Invalid(kind) }
            _ => { reader.skip_some(len); Self::Unsupported(kind) }
        };
        Ok(ContinueRead::Parsed(value))
    }
}
