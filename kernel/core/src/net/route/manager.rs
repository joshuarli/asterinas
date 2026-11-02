// SPDX-License-Identifier: MPL-2.0

use super::{
    RouteAddressFamily, RouteEntry, RouteLookupKey, RouteMetric, RouteProtocol, RouteTableId,
    rule::{Rule, RuleAction, RulePriority},
    table::RouteTable,
};
use crate::prelude::*;

/// The manager that owns the routing policy rules and tables for one IP address family.
pub(super) struct RouteManager<A: RouteAddressFamily> {
    rules: BTreeMap<RulePriority, Vec<Rule>>,
    tables: BTreeMap<RouteTableId, RouteTable<A>>,
}

impl<A: RouteAddressFamily> RouteManager<A> {
    pub(super) fn new(default_rules: &[Rule], routes: Vec<RouteEntry<A>>) -> Self {
        let mut rules = BTreeMap::<RulePriority, Vec<Rule>>::new();
        let mut tables = BTreeMap::new();

        for rule in default_rules {
            if let RuleAction::Lookup(table_id) = rule.action() {
                tables.entry(*table_id).or_insert_with(RouteTable::new);
            }
            rules.entry(rule.priority()).or_default().push(rule.clone());
        }

        for route in routes {
            let table_id = route.table_id();
            tables
                .entry(table_id)
                .or_insert_with(RouteTable::new)
                .insert(route);
        }

        Self { rules, tables }
    }

    /// Replaces the routes of an interface.
    ///
    /// The kernel-derived routes of the interface are replaced by `derived_routes`. Routes that
    /// user space installed through the interface are kept only if `keep_user_routes` is set.
    pub(super) fn replace_iface_routes(
        &mut self,
        iface_index: u32,
        keep_user_routes: bool,
        derived_routes: Vec<RouteEntry<A>>,
    ) {
        for table in self.tables.values_mut() {
            table.retain(|entry| {
                entry.output_iface().index() != iface_index
                    || (keep_user_routes && entry.origin().protocol != RouteProtocol::KERNEL)
            });
        }
        for route in derived_routes {
            self.tables
                .entry(route.table_id())
                .or_insert_with(RouteTable::new)
                .insert(route);
        }
    }

    /// Inserts a route that user space installed; the route fails if it already exists.
    pub(super) fn insert_user_route(&mut self, entry: RouteEntry<A>) -> Result<()> {
        let table = self
            .tables
            .entry(entry.table_id())
            .or_insert_with(RouteTable::new);
        if table.get(entry.dst(), entry.metric()).is_some() {
            return_errno_with_message!(Errno::EEXIST, "the route already exists");
        }
        table.insert(entry);
        Ok(())
    }

    /// Returns the first route to `destination` in the table, by increasing metric, that
    /// satisfies the predicate.
    pub(super) fn find_route(
        &self,
        table_id: RouteTableId,
        destination: &A::Cidr,
        matches: impl Fn(&RouteEntry<A>) -> bool,
    ) -> Option<RouteEntry<A>> {
        self.tables
            .get(&table_id)?
            .routes_to(destination)
            .find(|entry| matches(entry))
            .cloned()
    }

    pub(super) fn remove_route(
        &mut self,
        table_id: RouteTableId,
        destination: &A::Cidr,
        metric: RouteMetric,
    ) {
        if let Some(table) = self.tables.get_mut(&table_id) {
            table.remove(destination, metric);
        }
    }

    pub(super) fn entries(&self) -> impl Iterator<Item = &RouteEntry<A>> {
        self.tables.values().flat_map(RouteTable::entries)
    }

    pub(super) fn rules(&self) -> impl Iterator<Item = &Rule> {
        self.rules.values().flatten()
    }

    pub(super) fn lookup_entry(&self, key: &RouteLookupKey<A>) -> Result<RouteEntry<A>> {
        for rules in self.rules.values() {
            for rule in rules {
                match rule.action() {
                    RuleAction::Lookup(table_id) => {
                        let Some(table) = self.tables.get(table_id) else {
                            continue;
                        };
                        if let Some(route) = table.lookup(key) {
                            return Ok(route);
                        }
                    }
                    RuleAction::Unreachable => {
                        return_errno_with_message!(
                            Errno::ENETUNREACH,
                            "the route rule rejects lookup"
                        );
                    }
                    RuleAction::Prohibit => {
                        return_errno_with_message!(
                            Errno::EACCES,
                            "the route rule prohibits lookup"
                        );
                    }
                    RuleAction::Blackhole => {
                        return_errno_with_message!(Errno::EINVAL, "the route rule discards lookup");
                    }
                }
            }
        }

        return_errno_with_message!(Errno::ENETUNREACH, "no route to the destination")
    }

    pub(super) fn lookup_in_local_table(&self, key: &RouteLookupKey<A>) -> Option<RouteEntry<A>> {
        self.tables.get(&RouteTableId::LOCAL)?.lookup(key)
    }
}
