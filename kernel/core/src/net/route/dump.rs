// SPDX-License-Identifier: MPL-2.0

use core::net::IpAddr;

use aster_bigtcp::wire::{Ipv4Address, Ipv6Address};

use super::{
    IPV4_ROUTE_MANAGER, IPV6_ROUTE_MANAGER, RouteAddressFamily, RouteEntry,
    entry::{RouteProtocol, RouteScope, RouteType},
    manager::RouteManager,
    rule::{MarkSelector, Rule, RuleAction},
};
use crate::prelude::*;

/// One route as it is reported to user space.
pub(in crate::net) struct RouteRecord {
    pub destination: IpAddr,
    pub destination_prefix_len: u8,
    pub gateway: Option<IpAddr>,
    pub preferred_source: Option<IpAddr>,
    pub iface_index: u32,
    pub table: u32,
    pub protocol: RouteProtocol,
    pub scope: RouteScope,
    pub type_: RouteType,
    pub priority: u32,
}

/// The routing decision of one policy rule as it is reported to user space.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::net) enum RuleOutcome {
    Lookup { table: u32 },
    Unreachable,
    Prohibit,
    Blackhole,
}

/// One policy rule as it is reported to user space.
pub(in crate::net) struct RuleRecord {
    pub is_ipv4: bool,
    pub priority: u32,
    pub outcome: RuleOutcome,
    pub mark: Option<MarkSelector>,
    pub protocol: u8,
}

/// Returns the IPv4 routes, then the IPv6 routes, in table order.
pub(in crate::net) fn dump_routes(ipv4: bool, ipv6: bool) -> Vec<RouteRecord> {
    let mut records = Vec::new();
    if ipv4 {
        records.extend(manager_records(&IPV4_ROUTE_MANAGER.get().unwrap().read()));
    }
    if ipv6 {
        records.extend(manager_records(&IPV6_ROUTE_MANAGER.get().unwrap().read()));
    }
    records
}

/// Returns the IPv4 rules, then the IPv6 rules, in priority order.
pub(in crate::net) fn dump_rules(ipv4: bool, ipv6: bool) -> Vec<RuleRecord> {
    let mut records = Vec::new();
    if ipv4 {
        records.extend(manager_rules(&IPV4_ROUTE_MANAGER.get().unwrap().read(), true));
    }
    if ipv6 {
        records.extend(manager_rules(&IPV6_ROUTE_MANAGER.get().unwrap().read(), false));
    }
    records
}

pub(super) trait IntoIpAddr: RouteAddressFamily {
    fn into_ip_addr(self) -> IpAddr;
    fn cidr_parts(cidr: &Self::Cidr) -> (IpAddr, u8);
}

impl IntoIpAddr for Ipv4Address {
    fn into_ip_addr(self) -> IpAddr {
        IpAddr::V4(self)
    }

    fn cidr_parts(cidr: &Self::Cidr) -> (IpAddr, u8) {
        (IpAddr::V4(cidr.address()), cidr.prefix_len())
    }
}

impl IntoIpAddr for Ipv6Address {
    fn into_ip_addr(self) -> IpAddr {
        IpAddr::V6(self)
    }

    fn cidr_parts(cidr: &Self::Cidr) -> (IpAddr, u8) {
        (IpAddr::V6(cidr.address()), cidr.prefix_len())
    }
}

fn manager_records<A: IntoIpAddr>(manager: &RouteManager<A>) -> Vec<RouteRecord> {
    manager.entries().map(entry_record).collect()
}

pub(super) fn entry_record<A: IntoIpAddr>(entry: &RouteEntry<A>) -> RouteRecord {
    let (destination, destination_prefix_len) = A::cidr_parts(entry.dst());
    RouteRecord {
        destination,
        destination_prefix_len,
        gateway: entry.gateway().map(A::into_ip_addr),
        preferred_source: entry.origin().preferred_source.map(A::into_ip_addr),
        iface_index: entry.output_iface().index(),
        table: entry.table_id().get(),
        protocol: entry.origin().protocol,
        scope: entry.origin().scope,
        type_: entry.type_(),
        priority: entry.metric().get(),
    }
}

fn manager_rules<A: RouteAddressFamily>(manager: &RouteManager<A>, is_ipv4: bool) -> Vec<RuleRecord> {
    manager.rules().map(|rule| rule_record(rule, is_ipv4)).collect()
}

pub(super) fn rule_record(rule: &Rule, is_ipv4: bool) -> RuleRecord {
    RuleRecord {
        is_ipv4,
        priority: rule.priority().get(),
        outcome: match rule.action() {
            RuleAction::Lookup(table) => RuleOutcome::Lookup { table: table.get() },
            RuleAction::Unreachable => RuleOutcome::Unreachable,
            RuleAction::Prohibit => RuleOutcome::Prohibit,
            RuleAction::Blackhole => RuleOutcome::Blackhole,
        },
        mark: rule.mark(),
        protocol: rule.protocol(),
    }
}
