// SPDX-License-Identifier: MPL-2.0

use super::RouteTableId;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct Rule {
    priority: RulePriority,
    action: RuleAction,
    mark: Option<MarkSelector>,
    protocol: u8,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::net) struct MarkSelector {
    pub value: u32,
    pub mask: u32,
}

impl Rule {
    pub(super) const fn lookup(priority: u32, table: RouteTableId) -> Self {
        Self { priority: RulePriority::new(priority), action: RuleAction::Lookup(table), mark: None, protocol: 2 }
    }

    pub(super) const fn new(priority: u32, action: RuleAction, mark: Option<MarkSelector>, protocol: u8) -> Self {
        Self { priority: RulePriority::new(priority), action, mark, protocol }
    }

    pub(super) const fn priority(&self) -> RulePriority { self.priority }
    pub(super) const fn action(&self) -> &RuleAction { &self.action }
    pub(super) const fn mark(&self) -> Option<MarkSelector> { self.mark }
    pub(super) const fn protocol(&self) -> u8 { self.protocol }
    pub(super) fn matches_mark(&self, mark: u32) -> bool {
        self.mark.is_none_or(|selector| (selector.value ^ mark) & selector.mask == 0)
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(super) struct RulePriority(u32);

impl RulePriority {
    pub(super) const fn get(self) -> u32 { self.0 }
    pub(super) const fn new(priority: u32) -> Self { Self(priority) }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum RuleAction {
    Lookup(RouteTableId),
    Unreachable,
    Prohibit,
    Blackhole,
}
