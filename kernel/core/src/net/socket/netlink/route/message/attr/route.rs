// SPDX-License-Identifier: MPL-2.0

use core::net::IpAddr;

use crate::{
    net::socket::netlink::message::{Attribute, CAttrHeader, ContinueRead},
    prelude::*,
    util::MultiRead,
};

/// Route-related attributes.
///
/// Reference: <https://elixir.bootlin.com/linux/v7.1/source/include/uapi/linux/rtnetlink.h>.
#[expect(non_camel_case_types)]
#[expect(clippy::upper_case_acronyms)]
#[repr(u16)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, TryFromInt)]
enum RouteAttrClass {
    UNSPEC = 0,
    DST = 1,
    SRC = 2,
    IIF = 3,
    OIF = 4,
    GATEWAY = 5,
    PRIORITY = 6,
    PREFSRC = 7,
    METRICS = 8,
    MULTIPATH = 9,
    PROTOINFO = 10,
    FLOW = 11,
    CACHEINFO = 12,
    SESSION = 13,
    MP_ALGO = 14,
    TABLE = 15,
    MARK = 16,
    MFC_STATS = 17,
    VIA = 18,
    NEWDST = 19,
    PREF = 20,
}

/// The size of `struct rta_cacheinfo`.
const CACHE_INFO_LEN: usize = 32;

#[derive(Debug)]
pub(crate) enum RouteAttr {
    Table(u32),
    Dst(IpAddr),
    Priority(u32),
    PrefSrc(IpAddr),
    Gateway(IpAddr),
    Oif(u32),
    CacheInfo([u8; CACHE_INFO_LEN]),
    Pref(u8),
}

impl RouteAttr {
    /// Creates the all-zero cache information that Linux reports for a route without a cache entry.
    pub(crate) const fn empty_cache_info() -> Self {
        Self::CacheInfo([0; CACHE_INFO_LEN])
    }

    fn class(&self) -> RouteAttrClass {
        match self {
            RouteAttr::Table(_) => RouteAttrClass::TABLE,
            RouteAttr::Dst(_) => RouteAttrClass::DST,
            RouteAttr::Priority(_) => RouteAttrClass::PRIORITY,
            RouteAttr::PrefSrc(_) => RouteAttrClass::PREFSRC,
            RouteAttr::Gateway(_) => RouteAttrClass::GATEWAY,
            RouteAttr::Oif(_) => RouteAttrClass::OIF,
            RouteAttr::CacheInfo(_) => RouteAttrClass::CACHEINFO,
            RouteAttr::Pref(_) => RouteAttrClass::PREF,
        }
    }
}

impl Attribute for RouteAttr {
    fn type_(&self) -> u16 {
        self.class() as u16
    }

    fn payload_as_bytes(&self) -> &[u8] {
        match self {
            RouteAttr::Table(value) | RouteAttr::Priority(value) | RouteAttr::Oif(value) => {
                value.as_bytes()
            }
            RouteAttr::Dst(address) | RouteAttr::PrefSrc(address) | RouteAttr::Gateway(address) => {
                address.as_octets()
            }
            RouteAttr::CacheInfo(bytes) => bytes,
            RouteAttr::Pref(value) => value.as_bytes(),
        }
    }

    fn read_from(header: &CAttrHeader, reader: &mut dyn MultiRead) -> Result<ContinueRead<Self>>
    where
        Self: Sized,
    {
        let payload_len = header.payload_len();

        let Ok(class) = RouteAttrClass::try_from(header.type_()) else {
            // Unknown attributes should be ignored.
            // Reference: <https://docs.kernel.org/userspace-api/netlink/intro.html#unknown-attributes>.
            reader.skip_some(payload_len);
            return Ok(ContinueRead::Skipped);
        };

        let attr = match (class, payload_len) {
            (RouteAttrClass::TABLE, 4) => Self::Table(reader.read_val_opt::<u32>()?.unwrap()),
            (RouteAttrClass::PRIORITY, 4) => {
                Self::Priority(reader.read_val_opt::<u32>()?.unwrap())
            }
            (RouteAttrClass::OIF, 4) => Self::Oif(reader.read_val_opt::<u32>()?.unwrap()),
            (RouteAttrClass::PREF, 1) => Self::Pref(reader.read_val_opt::<u8>()?.unwrap()),
            (RouteAttrClass::DST | RouteAttrClass::GATEWAY, 4) => {
                let address = IpAddr::from(reader.read_val_opt::<[u8; 4]>()?.unwrap());
                if class == RouteAttrClass::DST {
                    Self::Dst(address)
                } else {
                    Self::Gateway(address)
                }
            }
            (RouteAttrClass::DST | RouteAttrClass::GATEWAY, 16) => {
                let address = IpAddr::from(reader.read_val_opt::<[u8; 16]>()?.unwrap());
                if class == RouteAttrClass::DST {
                    Self::Dst(address)
                } else {
                    Self::Gateway(address)
                }
            }
            (
                RouteAttrClass::TABLE
                | RouteAttrClass::PRIORITY
                | RouteAttrClass::OIF
                | RouteAttrClass::PREF
                | RouteAttrClass::DST
                | RouteAttrClass::GATEWAY,
                _,
            ) => {
                reader.skip_some(payload_len);
                return Ok(ContinueRead::skipped_with_error(
                    Errno::EINVAL,
                    "the route attribute is invalid",
                ));
            }
            (RouteAttrClass::UNSPEC | RouteAttrClass::CACHEINFO, _) => {
                reader.skip_some(payload_len);
                return Ok(ContinueRead::Skipped);
            }
            (_, _) => {
                reader.skip_some(payload_len);
                return Ok(ContinueRead::skipped_with_error(
                    Errno::EOPNOTSUPP,
                    "the route attribute is not supported",
                ));
            }
        };

        Ok(ContinueRead::Parsed(attr))
    }
}
