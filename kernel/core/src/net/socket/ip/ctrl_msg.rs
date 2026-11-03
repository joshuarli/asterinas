// SPDX-License-Identifier: MPL-2.0

use core::time::Duration;

use crate::{
    net::socket::util::{CControlHeader, RecvFlags},
    prelude::*,
    time::{timespec_t, timeval_t},
    util::net::{CSocketAddrFamily, CSocketOptionLevel},
};

/// Control messages an IPv4 datagram socket delivers with a received message.
///
/// Reference: <https://man7.org/linux/man-pages/man7/ip.7.html> and
/// <https://www.kernel.org/doc/Documentation/networking/timestamping.txt>.
#[derive(Debug)]
pub(crate) enum IpControlMessage {
    TypeOfService(u8),
    /// `IP_PKTINFO`: the interface and addresses a datagram arrived on.
    PacketInfo { ifindex: i32, local: [u8; 4], destination: [u8; 4] },
    /// `SCM_TIMESTAMP`: the arrival time as a `timeval`.
    Timestamp(Duration),
    /// `SCM_TIMESTAMPNS`: the arrival time as a `timespec`.
    TimestampNs(Duration),
    /// `SCM_TIMESTAMPING`: the software time, with the unused deprecated and hardware slots zero.
    Timestamping(Duration),
    /// `IP_RECVERR` describing a transmit timestamp (`SO_EE_ORIGIN_TIMESTAMPING`).
    TimestampingError { tx_id: u32 },
    NetworkError { errno: u32, origin: u8, type_: u8, code: u8, info: u32, offender: Option<[u8; 4]> },
    TimeToLive(u8),
}

const SOL_IP_PKTINFO: i32 = 8;
const SOL_IP_TTL: i32 = 2;
const SOL_IP_TOS: i32 = 1;
const SOL_IP_RECVERR: i32 = 11;
const SCM_TIMESTAMP: i32 = 29;
const SCM_TIMESTAMPNS: i32 = 35;
const SCM_TIMESTAMPING: i32 = 37;
const SO_EE_ORIGIN_TIMESTAMPING: u8 = 4;
const SCM_TSTAMP_SND: u32 = 0;
const ENOMSG: u32 = 42;

#[repr(C)]
#[derive(Clone, Copy, Debug, Pod)]
struct InPktinfo {
    ifindex: i32,
    spec_dst: [u8; 4],
    addr: [u8; 4],
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Pod)]
struct ScmTimestamping {
    software: timespec_t,
    deprecated: timespec_t,
    hardware: timespec_t,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Pod)]
struct SockExtendedErr {
    errno: u32,
    origin: u8,
    type_: u8,
    code: u8,
    pad: u8,
    info: u32,
    data: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Pod)]
struct SockExtendedErrWithOffender {
    error: SockExtendedErr,
    family: u16,
    port: u16,
    address: [u8; 4],
    padding: [u8; 8],
}

impl IpControlMessage {
    pub(crate) fn write_to(&self, writer: &mut VmWriter) -> Result<(CControlHeader, RecvFlags)> {
        match self {
            Self::TypeOfService(tos) => write_payload(writer, CSocketOptionLevel::SOL_IP, SOL_IP_TOS, tos),
            Self::TimeToLive(ttl) => write_payload(
                writer,
                CSocketOptionLevel::SOL_IP,
                SOL_IP_TTL,
                &i32::from(*ttl),
            ),
            Self::PacketInfo { ifindex, local, destination } => write_payload(
                writer,
                CSocketOptionLevel::SOL_IP,
                SOL_IP_PKTINFO,
                &InPktinfo { ifindex: *ifindex, spec_dst: *local, addr: *destination },
            ),
            Self::Timestamp(time) => write_payload(
                writer,
                CSocketOptionLevel::SOL_SOCKET,
                SCM_TIMESTAMP,
                &timeval_t::from(*time),
            ),
            Self::TimestampNs(time) => write_payload(
                writer,
                CSocketOptionLevel::SOL_SOCKET,
                SCM_TIMESTAMPNS,
                &timespec_t::from(*time),
            ),
            Self::Timestamping(time) => write_payload(
                writer,
                CSocketOptionLevel::SOL_SOCKET,
                SCM_TIMESTAMPING,
                &ScmTimestamping {
                    software: timespec_t::from(*time),
                    deprecated: timespec_t::default(),
                    hardware: timespec_t::default(),
                },
            ),
            Self::TimestampingError { tx_id } => write_payload(
                writer,
                CSocketOptionLevel::SOL_IP,
                SOL_IP_RECVERR,
                &SockExtendedErr {
                    errno: ENOMSG,
                    origin: SO_EE_ORIGIN_TIMESTAMPING,
                    type_: 0,
                    code: 0,
                    pad: 0,
                    info: SCM_TSTAMP_SND,
                    data: *tx_id,
                },
            ),
            Self::NetworkError { errno, origin, type_, code, info, offender } => write_payload(
                writer,
                CSocketOptionLevel::SOL_IP,
                SOL_IP_RECVERR,
                &SockExtendedErrWithOffender {
                    error: SockExtendedErr { errno: *errno, origin: *origin, type_: *type_, code: *code, pad: 0, info: *info, data: 0 },
                    family: if offender.is_some() { CSocketAddrFamily::AF_INET as u16 } else { CSocketAddrFamily::AF_UNSPEC as u16 },
                    port: 0,
                    address: offender.unwrap_or([0; 4]),
                    padding: [0; 8],
                },
            ),
        }
    }
}

fn write_payload<T: Pod>(
    writer: &mut VmWriter,
    level: CSocketOptionLevel,
    type_: i32,
    payload: &T,
) -> Result<(CControlHeader, RecvFlags)> {
    if CControlHeader::payload_len_from_total(writer.avail())? < size_of::<T>() {
        return_errno_with_message!(Errno::EINVAL, "the control message buffer is too small");
    }

    let header = CControlHeader::new(level, type_, size_of::<T>());
    writer.write_val(&header)?;
    writer.write_val(payload)?;
    Ok((header, RecvFlags::empty()))
}
