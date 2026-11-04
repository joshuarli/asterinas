// SPDX-License-Identifier: MPL-2.0

use core::num::NonZeroU8;

use aster_bigtcp::socket::NeedIfacePoll;

use crate::{
    net::socket::options::{
        SocketOption,
        macros::{impl_socket_options, sock_option_mut, sock_option_ref},
    },
    prelude::*,
};

/// IP-level socket options.
#[derive(Clone, Copy, CopyGetters, Debug, Setters)]
#[get_copy = "pub"]
#[set = "pub"]
pub(super) struct IpOptionSet {
    tos: u8,
    ttl: IpTtl,
    hdrincl: bool,
    recverr: bool,
    recvttl: bool,
    recvtos: bool,
    pktinfo: bool,
}

const DEFAULT_TTL: u8 = 64;
pub(super) const INET_ECN_MASK: u8 = 3;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(i32)]
pub(super) enum PathMtuDiscovery {
    Dont = 0,
    Want = 1,
    Do = 2,
    Probe = 3,
    Interface = 4,
    Omit = 5,
}

impl TryFrom<i32> for PathMtuDiscovery {
    type Error = Error;

    fn try_from(value: i32) -> Result<Self> {
        match value {
            0 => Ok(Self::Dont),
            1 => Ok(Self::Want),
            2 => Ok(Self::Do),
            3 => Ok(Self::Probe),
            4 => Ok(Self::Interface),
            5 => Ok(Self::Omit),
            _ => return_errno_with_message!(Errno::EINVAL, "invalid path MTU discovery mode"),
        }
    }
}

impl IpOptionSet {
    pub(super) const fn new_tcp() -> Self {
        Self {
            tos: 0,
            ttl: IpTtl(None),
            hdrincl: false,
            recverr: false,
            recvttl: false,
            recvtos: false,
            pktinfo: false,
        }
    }

    pub(super) const fn new_udp() -> Self {
        Self {
            tos: 0,
            ttl: IpTtl(None),
            hdrincl: false,
            recverr: false,
            recvttl: false,
            recvtos: false,
            pktinfo: false,
        }
    }

    pub(super) fn get_option(&self, option: &mut dyn SocketOption) -> Result<()> {
        sock_option_mut!(match option {
            ip_tos @ Tos => {
                let tos = self.tos();
                ip_tos.set(tos as _);
            }
            ip_ttl @ Ttl => {
                let ttl = self.ttl();
                ip_ttl.set(ttl);
            }
            ip_hdrincl @ Hdrincl => {
                let hdrincl = self.hdrincl();
                ip_hdrincl.set(hdrincl);
            }
            ip_recverr @ Recverr => {
                let recverr = self.recverr();
                ip_recverr.set(recverr);
            }
            ip_recvttl @ RecvTtl => {
                ip_recvttl.set(self.recvttl());
            }
            ip_recvtos @ RecvTos => {
                ip_recvtos.set(self.recvtos());
            }
            ip_pktinfo @ Pktinfo => {
                let pktinfo = self.pktinfo();
                ip_pktinfo.set(pktinfo);
            }
            _ => return_errno_with_message!(Errno::ENOPROTOOPT, "the socket option is unknown"),
        });

        Ok(())
    }

    pub(super) fn set_option(
        &mut self,
        option: &dyn SocketOption,
        socket: &dyn SetIpLevelOption,
    ) -> Result<NeedIfacePoll> {
        sock_option_ref!(match option {
            ip_tos @ Tos => {
                let old_value = self.tos();
                let val = socket.tos_value(*ip_tos.get().unwrap() as u8, old_value);
                self.set_tos(val);
            }
            ip_ttl @ Ttl => {
                let ttl = ip_ttl.get().unwrap();
                self.set_ttl(*ttl);
            }
            ip_hdrincl @ Hdrincl => {
                let hdrincl = ip_hdrincl.get().unwrap();
                socket.set_hdrincl(*hdrincl)?;
                self.set_hdrincl(*hdrincl);
            }
            ip_recverr @ Recverr => {
                let recverr = ip_recverr.get().unwrap();
                self.set_recverr(*recverr);
            }
            ip_recvttl @ RecvTtl => {
                self.set_recvttl(*ip_recvttl.get().unwrap());
            }
            ip_recvtos @ RecvTos => {
                self.set_recvtos(*ip_recvtos.get().unwrap());
            }
            ip_pktinfo @ Pktinfo => {
                let pktinfo = ip_pktinfo.get().unwrap();
                self.set_pktinfo(*pktinfo);
            }
            _ => return_errno_with_message!(
                Errno::ENOPROTOOPT,
                "the socket option to be set is unknown"
            ),
        });

        Ok(NeedIfacePoll::FALSE)
    }
}

impl_socket_options!(
    pub(crate) struct Tos(i32);
    pub(crate) struct Ttl(IpTtl);
    pub(crate) struct Hdrincl(bool);
    pub(crate) struct Recverr(bool);
    pub(crate) struct RecvTtl(bool);
    pub(crate) struct RecvTos(bool);
    pub(crate) struct Pktinfo(bool);
    pub(crate) struct MtuDiscover(i32);
    pub(crate) struct Mtu(i32);
);

#[derive(Clone, Copy, Debug)]
pub(crate) struct IpTtl(Option<NonZeroU8>);

impl IpTtl {
    pub(crate) const fn new(val: Option<NonZeroU8>) -> Self {
        Self(val)
    }

    pub(crate) const fn get(&self) -> u8 {
        if let Some(val) = self.0 {
            val.get()
        } else {
            DEFAULT_TTL
        }
    }
}

pub(super) trait SetIpLevelOption {
    fn set_hdrincl(&self, _hdrincl: bool) -> Result<()>;

    fn tos_value(&self, requested: u8, _old: u8) -> u8 {
        requested
    }
}
