// SPDX-License-Identifier: MPL-2.0

use aster_bigtcp::{iface::InterfaceName, wire::EthernetAddress};
use zerocopy::Immutable;

use crate::{
    net::socket::netlink::message::{Attribute, CAttrHeader, ContinueRead},
    prelude::*,
    util::MultiRead,
};

const ETHERNET_ADDRESS_LEN: usize = 6;

/// The longest hardware address an `IFLA_ADDRESS` attribute may carry (`MAX_ADDR_LEN`).
const MAX_ADDRESS_LEN: usize = 32;

/// Link-level attributes.
///
/// Reference: <https://elixir.bootlin.com/linux/v6.13/source/include/uapi/linux/if_link.h#L297>.
#[expect(non_camel_case_types)]
#[expect(clippy::upper_case_acronyms)]
#[repr(u16)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, TryFromInt)]
enum LinkAttrClass {
    UNSPEC = 0,
    ADDRESS = 1,
    BROADCAST = 2,
    IFNAME = 3,
    MTU = 4,
    LINK = 5,
    QDISC = 6,
    STATS = 7,
    COST = 8,
    PRIORITY = 9,
    MASTER = 10,
    /// Wireless Extension event
    WIRELESS = 11,
    /// Protocol specific information for a link
    PROTINFO = 12,
    TXQLEN = 13,
    MAP = 14,
    WEIGHT = 15,
    OPERSTATE = 16,
    LINKMODE = 17,
    LINKINFO = 18,
    NET_NS_PID = 19,
    IFALIAS = 20,
    /// Number of VFs if device is SR-IOV PF
    NUM_VF = 21,
    VFINFO_LIST = 22,
    STATS64 = 23,
    VF_PORTS = 24,
    PORT_SELF = 25,
    AF_SPEC = 26,
    /// Group the device belongs to
    GROUP = 27,
    NET_NS_FD = 28,
    /// Extended info mask, VFs, etc.
    EXT_MASK = 29,
    /// Promiscuity count: > 0 means acts PROMISC
    PROMISCUITY = 30,
    NUM_TX_QUEUES = 31,
    NUM_RX_QUEUES = 32,
    CARRIER = 33,
    PHYS_PORT_ID = 34,
    CARRIER_CHANGES = 35,
    PHYS_SWITCH_ID = 36,
    LINK_NETNSID = 37,
    PHYS_PORT_NAME = 38,
    PROTO_DOWN = 39,
    GSO_MAX_SEGS = 40,
    GSO_MAX_SIZE = 41,
    PAD = 42,
    XDP = 43,
    EVENT = 44,
    NEW_NETNSID = 45,
    IF_NETNSID = 46,
    CARRIER_UP_COUNT = 47,
    CARRIER_DOWN_COUNT = 48,
    NEW_IFINDEX = 49,
    MIN_MTU = 50,
    MAX_MTU = 51,
    PROP_LIST = 52,
    /// Alternative ifname
    ALT_IFNAME = 53,
    PERM_ADDRESS = 54,
    PROTO_DOWN_REASON = 55,
    PARENT_DEV_NAME = 56,
    PARENT_DEV_BUS_NAME = 57,
}

/// The RFC 2863 operational state of a link.
///
/// Reference: <https://elixir.bootlin.com/linux/v7.1/source/include/uapi/linux/if.h>.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Immutable, IntoBytes)]
pub(crate) enum OperState {
    Unknown = 0,
    Down = 2,
    Up = 6,
}

macro_rules! link_stats {
    ($(#[$meta:meta])* $name:ident, $counter:ty $(, $extra:ident)*) => {
        $(#[$meta])*
        #[repr(C)]
        #[derive(Clone, Copy, Debug, Default, Immutable, IntoBytes)]
        pub(crate) struct $name {
            pub(crate) rx_packets: $counter,
            pub(crate) tx_packets: $counter,
            pub(crate) rx_bytes: $counter,
            pub(crate) tx_bytes: $counter,
            pub(crate) rx_errors: $counter,
            pub(crate) tx_errors: $counter,
            pub(crate) rx_dropped: $counter,
            pub(crate) tx_dropped: $counter,
            pub(crate) multicast: $counter,
            pub(crate) collisions: $counter,
            pub(crate) rx_length_errors: $counter,
            pub(crate) rx_over_errors: $counter,
            pub(crate) rx_crc_errors: $counter,
            pub(crate) rx_frame_errors: $counter,
            pub(crate) rx_fifo_errors: $counter,
            pub(crate) rx_missed_errors: $counter,
            pub(crate) tx_aborted_errors: $counter,
            pub(crate) tx_carrier_errors: $counter,
            pub(crate) tx_fifo_errors: $counter,
            pub(crate) tx_heartbeat_errors: $counter,
            pub(crate) tx_window_errors: $counter,
            pub(crate) rx_compressed: $counter,
            pub(crate) tx_compressed: $counter,
            pub(crate) rx_nohandler: $counter,
            $(pub(crate) $extra: $counter,)*
        }
    };
}

link_stats!(
    /// `struct rtnl_link_stats64` in Linux.
    ///
    /// Reference: <https://elixir.bootlin.com/linux/v7.1/source/include/uapi/linux/if_link.h>.
    CLinkStats64,
    u64,
    rx_otherhost_dropped
);

link_stats!(
    /// `struct rtnl_link_stats` in Linux, whose counters wrap at 32 bits.
    ///
    /// Unlike [`CLinkStats64`], it has no `rx_otherhost_dropped` counter.
    ///
    /// Reference: <https://elixir.bootlin.com/linux/v7.1/source/include/uapi/linux/if_link.h>.
    CLinkStats,
    u32
);

const _: () = assert!(size_of::<CLinkStats64>() == 200 && size_of::<CLinkStats>() == 96);

impl CLinkStats64 {
    /// Returns the counters truncated to 32 bits, as Linux copies them into `IFLA_STATS`.
    pub(crate) fn truncated(&self) -> CLinkStats {
        CLinkStats {
            rx_packets: self.rx_packets as u32,
            tx_packets: self.tx_packets as u32,
            rx_bytes: self.rx_bytes as u32,
            tx_bytes: self.tx_bytes as u32,
            rx_errors: self.rx_errors as u32,
            tx_errors: self.tx_errors as u32,
            rx_dropped: self.rx_dropped as u32,
            tx_dropped: self.tx_dropped as u32,
            multicast: self.multicast as u32,
            collisions: self.collisions as u32,
            rx_length_errors: self.rx_length_errors as u32,
            rx_over_errors: self.rx_over_errors as u32,
            rx_crc_errors: self.rx_crc_errors as u32,
            rx_frame_errors: self.rx_frame_errors as u32,
            rx_fifo_errors: self.rx_fifo_errors as u32,
            rx_missed_errors: self.rx_missed_errors as u32,
            tx_aborted_errors: self.tx_aborted_errors as u32,
            tx_carrier_errors: self.tx_carrier_errors as u32,
            tx_fifo_errors: self.tx_fifo_errors as u32,
            tx_heartbeat_errors: self.tx_heartbeat_errors as u32,
            tx_window_errors: self.tx_window_errors as u32,
            rx_compressed: self.rx_compressed as u32,
            tx_compressed: self.tx_compressed as u32,
            rx_nohandler: self.rx_nohandler as u32,
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) enum LinkAttr {
    // FIXME: Linux link-layer addresses have device-specific lengths.
    // Using `EthernetAddress` may be inappropriate
    // once Asterinas supports other network device types.
    Address(EthernetAddress),
    Broadcast(EthernetAddress),
    Name(InterfaceName),
    Mtu(u32),
    TxqLen(u32),
    OperState(OperState),
    Carrier(u8),
    CarrierChanges(u32),
    CarrierUpCount(u32),
    CarrierDownCount(u32),
    Stats64(CLinkStats64),
    Stats(CLinkStats),
    LinkMode(u8),
    ExtMask(RtExtFilter),
}

impl LinkAttr {
    fn class(&self) -> LinkAttrClass {
        match self {
            LinkAttr::Address(_) => LinkAttrClass::ADDRESS,
            LinkAttr::Broadcast(_) => LinkAttrClass::BROADCAST,
            LinkAttr::Name(_) => LinkAttrClass::IFNAME,
            LinkAttr::Mtu(_) => LinkAttrClass::MTU,
            LinkAttr::TxqLen(_) => LinkAttrClass::TXQLEN,
            LinkAttr::OperState(_) => LinkAttrClass::OPERSTATE,
            LinkAttr::Carrier(_) => LinkAttrClass::CARRIER,
            LinkAttr::CarrierChanges(_) => LinkAttrClass::CARRIER_CHANGES,
            LinkAttr::CarrierUpCount(_) => LinkAttrClass::CARRIER_UP_COUNT,
            LinkAttr::CarrierDownCount(_) => LinkAttrClass::CARRIER_DOWN_COUNT,
            LinkAttr::Stats64(_) => LinkAttrClass::STATS64,
            LinkAttr::Stats(_) => LinkAttrClass::STATS,
            LinkAttr::LinkMode(_) => LinkAttrClass::LINKMODE,
            LinkAttr::ExtMask(_) => LinkAttrClass::EXT_MASK,
        }
    }
}

impl Attribute for LinkAttr {
    fn type_(&self) -> u16 {
        self.class() as u16
    }

    fn payload_as_bytes(&self) -> &[u8] {
        match self {
            LinkAttr::Address(address) => &address.0,
            LinkAttr::Broadcast(address) => &address.0,
            LinkAttr::Name(name) => name.as_bytes_with_nul(),
            LinkAttr::Mtu(mtu) => mtu.as_bytes(),
            LinkAttr::TxqLen(txq_len) => txq_len.as_bytes(),
            LinkAttr::OperState(state) => state.as_bytes(),
            LinkAttr::Carrier(carrier) => carrier.as_bytes(),
            LinkAttr::CarrierChanges(count)
            | LinkAttr::CarrierUpCount(count)
            | LinkAttr::CarrierDownCount(count) => count.as_bytes(),
            LinkAttr::Stats64(stats) => stats.as_bytes(),
            LinkAttr::Stats(stats) => stats.as_bytes(),
            LinkAttr::LinkMode(link_mode) => link_mode.as_bytes(),
            LinkAttr::ExtMask(ext_filter) => ext_filter.as_bytes(),
        }
    }

    fn read_from(header: &CAttrHeader, reader: &mut dyn MultiRead) -> Result<ContinueRead<Self>>
    where
        Self: Sized,
    {
        let payload_len = header.payload_len();

        // TODO: Currently, `IS_NET_BYTEORDER_MASK` and `IS_NESTED_MASK` are ignored.
        let Ok(class) = LinkAttrClass::try_from(header.type_()) else {
            // Unknown attributes should be ignored.
            // Reference: <https://docs.kernel.org/userspace-api/netlink/intro.html#unknown-attributes>.
            reader.skip_some(payload_len);
            return Ok(ContinueRead::Skipped);
        };

        let res = match (class, payload_len) {
            (LinkAttrClass::IFNAME, 1..=InterfaceName::MAX_BYTES_WITH_NUL) => {
                let mut name_bytes = [0u8; InterfaceName::MAX_BYTES_WITH_NUL];

                let mut writer = VmWriter::from(&mut name_bytes[..payload_len]);
                reader.read(&mut writer)?;

                if !name_bytes.contains(&0) {
                    return Ok(ContinueRead::skipped_with_error(
                        Errno::ERANGE,
                        "the link attribute is invalid",
                    ));
                }

                let name = InterfaceName::from_bytes_until_nul(&name_bytes);
                Self::Name(name)
            }
            (LinkAttrClass::ADDRESS, ETHERNET_ADDRESS_LEN..=MAX_ADDRESS_LEN) => {
                let mut address = [0u8; ETHERNET_ADDRESS_LEN];
                reader.read(&mut VmWriter::from(&mut address[..]))?;
                reader.skip_some(payload_len - ETHERNET_ADDRESS_LEN);
                Self::Address(EthernetAddress(address))
            }
            (LinkAttrClass::MTU, 4) => Self::Mtu(reader.read_val_opt::<u32>()?.unwrap()),
            (LinkAttrClass::TXQLEN, 4) => Self::TxqLen(reader.read_val_opt::<u32>()?.unwrap()),
            (LinkAttrClass::LINKMODE, 1) => Self::LinkMode(reader.read_val_opt::<u8>()?.unwrap()),
            (LinkAttrClass::EXT_MASK, 4) => {
                const { assert!(size_of::<RtExtFilter>() == 4) };
                Self::ExtMask(reader.read_val_opt::<RtExtFilter>()?.unwrap())
            }

            (
                LinkAttrClass::IFNAME
                | LinkAttrClass::MTU
                | LinkAttrClass::TXQLEN
                | LinkAttrClass::LINKMODE
                | LinkAttrClass::EXT_MASK,
                _,
            ) => {
                warn!("link attribute `{:?}` contains invalid payload", class);
                reader.skip_some(payload_len);
                return Ok(ContinueRead::skipped_with_error(
                    if class == LinkAttrClass::IFNAME {
                        Errno::ERANGE
                    } else {
                        Errno::EINVAL
                    },
                    "the link attribute is invalid",
                ));
            }

            (_, _) => {
                warn!("link attribute `{:?}` is not supported", class);
                reader.skip_some(payload_len);
                return Ok(ContinueRead::Skipped);
            }
        };

        Ok(ContinueRead::Parsed(res))
    }
}

bitflags! {
    /// New extended info filters for [`NlLinkAttr::ExtMask`].
    ///
    /// Reference: <https://elixir.bootlin.com/linux/v6.13/source/include/uapi/linux/rtnetlink.h#L819>.
    #[repr(C)]
    #[derive(Pod)]
    pub(crate) struct RtExtFilter: u32 {
        const VF = 1 << 0;
        const BRVLAN = 1 << 1;
        const BRVLAN_COMPRESSED = 1 << 2;
        const SKIP_STATS = 1 << 3;
        const MRP = 1 << 4;
        const CFM_CONFIG = 1 << 5;
        const CFM_STATUS = 1 << 6;
        const MST = 1 << 7;
    }
}
