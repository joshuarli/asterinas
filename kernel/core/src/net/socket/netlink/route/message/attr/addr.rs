// SPDX-License-Identifier: MPL-2.0

use core::net::{IpAddr, Ipv4Addr};

use zerocopy::Immutable;

use crate::{
    net::socket::netlink::{
        message::{Attribute, CAttrHeader, ContinueRead},
        route::message::AddrMessageFlags,
    },
    prelude::*,
    util::MultiRead,
};

/// Address-related attributes.
///
/// Reference: <https://elixir.bootlin.com/linux/v6.13/source/include/uapi/linux/if_addr.h#L26>.
#[expect(non_camel_case_types)]
#[expect(clippy::upper_case_acronyms)]
#[repr(u16)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, TryFromInt)]
enum AddrAttrClass {
    UNSPEC = 0,
    ADDRESS = 1,
    LOCAL = 2,
    LABEL = 3,
    BROADCAST = 4,
    ANYCAST = 5,
    CACHEINFO = 6,
    MULTICAST = 7,
    FLAGS = 8,
    RT_PRIORITY = 9,
    TARGET_NETNSID = 10,
    PROTO = 11,
}

/// The source protocol of an interface address.
///
/// Reference: <https://elixir.bootlin.com/linux/v7.1/source/include/uapi/linux/if_addr.h#L73>.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Immutable, IntoBytes)]
pub(crate) enum AddrProtocol {
    /// An unspecified address source.
    #[expect(dead_code)]
    Unspecified = 0,
    /// A loopback address configured by the kernel.
    KernelLoopback = 1,
    /// An address configured by the kernel from a Router Advertisement.
    #[expect(dead_code)]
    KernelRouterAdvertisement = 2,
    /// A link-local address configured by the kernel.
    #[expect(dead_code)]
    KernelLinkLocal = 3,
}

/// `struct ifa_cacheinfo` in Linux.
///
/// Reference: <https://elixir.bootlin.com/linux/v7.1/source/include/uapi/linux/if_addr.h>.
#[repr(C)]
#[derive(Clone, Copy, Debug, Immutable, IntoBytes)]
pub(crate) struct AddrCacheInfo {
    /// The preferred lifetime in seconds, or `u32::MAX` for forever.
    pub preferred: u32,
    /// The valid lifetime in seconds, or `u32::MAX` for forever.
    pub valid: u32,
    /// The creation time in hundredths of a second since boot.
    pub created: u32,
    /// The update time in hundredths of a second since boot.
    pub updated: u32,
}

/// The lifetime of an address that does not expire.
pub(crate) const INFINITE_LIFETIME: u32 = u32::MAX;

#[derive(Clone, Debug)]
pub(crate) enum AddrAttr {
    Address(IpAddr),
    Broadcast(Ipv4Addr),
    CacheInfo(AddrCacheInfo),
    Flags(AddrMessageFlags),
    Label(CString),
    Local(IpAddr),
    Protocol(AddrProtocol),
}

impl AddrAttr {
    fn class(&self) -> AddrAttrClass {
        match self {
            AddrAttr::Address(_) => AddrAttrClass::ADDRESS,
            AddrAttr::Broadcast(_) => AddrAttrClass::BROADCAST,
            AddrAttr::CacheInfo(_) => AddrAttrClass::CACHEINFO,
            AddrAttr::Flags(_) => AddrAttrClass::FLAGS,
            AddrAttr::Label(_) => AddrAttrClass::LABEL,
            AddrAttr::Local(_) => AddrAttrClass::LOCAL,
            AddrAttr::Protocol(_) => AddrAttrClass::PROTO,
        }
    }
}

fn invalid_attr(
    reader: &mut dyn MultiRead,
    payload_len: usize,
    errno: Errno,
) -> Result<ContinueRead<AddrAttr>> {
    reader.skip_some(payload_len);
    Ok(ContinueRead::skipped_with_error(
        errno,
        "the address attribute is invalid",
    ))
}

fn read_ip_addr(payload_len: usize, reader: &mut dyn MultiRead) -> Result<Option<IpAddr>> {
    Ok(match payload_len {
        4 => Some(IpAddr::V4(Ipv4Addr::from(
            reader.read_val_opt::<[u8; 4]>()?.unwrap(),
        ))),
        16 => Some(IpAddr::V6(core::net::Ipv6Addr::from(
            reader.read_val_opt::<[u8; 16]>()?.unwrap(),
        ))),
        _ => {
            reader.skip_some(payload_len);
            None
        }
    })
}

impl Attribute for AddrAttr {
    fn type_(&self) -> u16 {
        self.class() as u16
    }

    fn payload_as_bytes(&self) -> &[u8] {
        match self {
            AddrAttr::Address(address) => address.as_octets(),
            AddrAttr::Broadcast(address) => address.as_octets(),
            AddrAttr::CacheInfo(info) => info.as_bytes(),
            AddrAttr::Flags(flags) => flags.as_bytes(),
            AddrAttr::Label(label) => label.as_bytes_with_nul(),
            AddrAttr::Local(address) => address.as_octets(),
            AddrAttr::Protocol(protocol) => protocol.as_bytes(),
        }
    }

    fn read_from(header: &CAttrHeader, reader: &mut dyn MultiRead) -> Result<ContinueRead<Self>>
    where
        Self: Sized,
    {
        let payload_len = header.payload_len();

        let Ok(class) = AddrAttrClass::try_from(header.type_()) else {
            // Unknown attributes should be ignored.
            // Reference: <https://docs.kernel.org/userspace-api/netlink/intro.html#unknown-attributes>.
            reader.skip_some(payload_len);
            return Ok(ContinueRead::Skipped);
        };

        let attr = match class {
            AddrAttrClass::ADDRESS | AddrAttrClass::LOCAL => {
                let Some(address) = read_ip_addr(payload_len, reader)? else {
                    return Ok(ContinueRead::skipped_with_error(
                        Errno::EINVAL,
                        "the address attribute is invalid",
                    ));
                };
                if class == AddrAttrClass::ADDRESS {
                    Self::Address(address)
                } else {
                    Self::Local(address)
                }
            }
            AddrAttrClass::BROADCAST if payload_len == 4 => {
                Self::Broadcast(Ipv4Addr::from(reader.read_val_opt::<[u8; 4]>()?.unwrap()))
            }
            AddrAttrClass::LABEL if (1..=16).contains(&payload_len) => {
                let mut label = [0u8; 16];
                let mut writer = VmWriter::from(&mut label[..payload_len]);
                reader.read(&mut writer)?;
                let text_len = label[..payload_len]
                    .iter()
                    .position(|byte| *byte == 0)
                    .unwrap_or(payload_len);
                if text_len == 16 {
                    return Ok(ContinueRead::skipped_with_error(
                        Errno::EINVAL,
                        "the address label is too long",
                    ));
                }
                let Ok(label) = CString::new(&label[..text_len]) else {
                    return Ok(ContinueRead::skipped_with_error(
                        Errno::EINVAL,
                        "the address label is invalid",
                    ));
                };
                Self::Label(label)
            }
            AddrAttrClass::FLAGS if payload_len == 4 => {
                let bits = reader.read_val_opt::<u32>()?.unwrap();
                let Some(flags) = AddrMessageFlags::from_bits(bits) else {
                    return Ok(ContinueRead::skipped_with_error(
                        Errno::EINVAL,
                        "the address flags are invalid",
                    ));
                };
                Self::Flags(flags)
            }
            AddrAttrClass::CACHEINFO if payload_len == size_of::<AddrCacheInfo>() => {
                let [preferred, valid, created, updated] =
                    reader.read_val_opt::<[u32; 4]>()?.unwrap();
                Self::CacheInfo(AddrCacheInfo {
                    preferred,
                    valid,
                    created,
                    updated,
                })
            }
            AddrAttrClass::ADDRESS
            | AddrAttrClass::LOCAL
            | AddrAttrClass::BROADCAST
            | AddrAttrClass::LABEL
            | AddrAttrClass::FLAGS
            | AddrAttrClass::CACHEINFO => return invalid_attr(reader, payload_len, Errno::EINVAL),
            AddrAttrClass::UNSPEC => {
                reader.skip_some(payload_len);
                return Ok(ContinueRead::Skipped);
            }
            AddrAttrClass::ANYCAST
            | AddrAttrClass::MULTICAST
            | AddrAttrClass::RT_PRIORITY
            | AddrAttrClass::TARGET_NETNSID
            | AddrAttrClass::PROTO => return invalid_attr(reader, payload_len, Errno::EOPNOTSUPP),
        };

        Ok(ContinueRead::Parsed(attr))
    }
}
