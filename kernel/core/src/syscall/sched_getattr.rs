// SPDX-License-Identifier: MPL-2.0

use ostd::{const_assert, mm::VmIo};

use super::{
    SyscallReturn,
    sched_get_priority_max::{rt_to_static, sched_priority_range, static_to_rt},
};
use crate::{
    prelude::*,
    process::{ResourceType, UserNamespace, credentials::capabilities::CapSet, pid_table, posix_thread::AsPosixThread},
    sched::{LinuxSchedPolicy, Nice, RealTimePolicy, SchedAttr, SchedPolicy, UserFairPolicy, UserSchedAttr},
    security::lsm::hooks as lsm_hooks,
    thread::{Thread, Tid},
    util::CopyCompat,
};

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Pod)]
pub(super) struct LinuxSchedAttr {
    // Size of this structure
    pub(super) size: u32,

    // Policy (SCHED_*)
    pub(super) sched_policy: u32,
    // Flags
    pub(super) sched_flags: u64,

    // Nice value (SCHED_NORMAL, SCHED_BATCH)
    pub(super) sched_nice: i32,

    // Static priority (SCHED_FIFO, SCHED_RR)
    pub(super) sched_priority: u32,

    // For SCHED_DEADLINE
    pub(super) sched_runtime: u64,
    pub(super) sched_deadline: u64,
    pub(super) sched_period: u64,

    // Utilization hints
    pub(super) sched_util_min: u32,
    pub(super) sched_util_max: u32,
}

// Reference: <https://elixir.bootlin.com/linux/v6.17.7/source/include/uapi/linux/sched.h#L120>
pub(super) const SCHED_RESET_ON_FORK: u32 = 0x4000_0000;
// Reference: <https://elixir.bootlin.com/linux/v6.17.7/source/include/uapi/linux/sched.h#L130>
const SCHED_FLAG_RESET_ON_FORK: u64 = 0x1;

// Reference: <https://elixir.bootlin.com/linux/v6.17.7/source/kernel/sched/syscalls.c#L331>
const MIN_FAIR_SLICE_NS: u64 = 100_000;
const MAX_FAIR_SLICE_NS: u64 = 100_000_000;

// Reference: <https://elixir.bootlin.com/linux/v6.17.7/source/include/uapi/linux/sched/types.h#L7>
const SCHED_ATTR_SIZE_VER0: u32 = 48;
// Reference: <https://elixir.bootlin.com/linux/v6.17.7/source/include/uapi/linux/sched/types.h#L8>
const SCHED_ATTR_SIZE_VER1: u32 = 56;

const_assert!(size_of::<LinuxSchedAttr>() == SCHED_ATTR_SIZE_VER1 as usize);

impl TryFrom<SchedPolicy> for LinuxSchedAttr {
    type Error = Error;

    fn try_from(value: SchedPolicy) -> Result<Self> {
        Ok(match value {
            SchedPolicy::Stop => LinuxSchedAttr {
                sched_policy: LinuxSchedPolicy::Fifo as u32,
                sched_priority: 99, // Linux uses 99 as the default priority for STOP tasks.
                ..Default::default()
            },

            SchedPolicy::RealTime { rt_prio, rt_policy } => LinuxSchedAttr {
                sched_policy: match rt_policy {
                    RealTimePolicy::Fifo => LinuxSchedPolicy::Fifo,
                    RealTimePolicy::RoundRobin { .. } => LinuxSchedPolicy::RoundRobin,
                } as u32,
                sched_priority: rt_to_static(rt_prio),
                ..Default::default()
            },

            // The SCHED_IDLE policy is mapped to the highest nice value of
            // `SchedPolicy::Fair` instead of `SchedPolicy::Idle`. Tasks of the
            // latter policy are invisible to the user API.
            SchedPolicy::Fair(Nice::MAX) => LinuxSchedAttr {
                sched_policy: LinuxSchedPolicy::Idle as u32,
                sched_nice: Nice::MAX.value().get().into(),
                ..Default::default()
            },

            SchedPolicy::Fair(nice) => LinuxSchedAttr {
                sched_policy: LinuxSchedPolicy::Normal as u32,
                sched_nice: nice.value().get().into(),
                ..Default::default()
            },

            SchedPolicy::Idle => return_errno_with_message!(
                Errno::EACCES,
                "scheduling attributes for idle tasks are not accessible"
            ),
        })
    }
}

impl TryFrom<LinuxSchedAttr> for SchedPolicy {
    type Error = Error;

    fn try_from(value: LinuxSchedAttr) -> Result<Self> {
        let linux_policy = LinuxSchedPolicy::try_from(value.sched_policy)?;

        Ok(match linux_policy {
            LinuxSchedPolicy::Fifo | LinuxSchedPolicy::RoundRobin => SchedPolicy::RealTime {
                rt_prio: static_to_rt(value.sched_priority)?,
                rt_policy: match linux_policy {
                    LinuxSchedPolicy::Fifo => RealTimePolicy::Fifo,
                    LinuxSchedPolicy::RoundRobin => RealTimePolicy::RoundRobin {
                        base_slice_factor: None,
                    },
                    _ => unreachable!(),
                },
            },

            _ if value.sched_priority != 0 => {
                return_errno_with_message!(Errno::EINVAL, "invalid scheduling priority")
            }

            LinuxSchedPolicy::Normal | LinuxSchedPolicy::Batch => SchedPolicy::Fair(Nice::new(
                i8::try_from(value.sched_nice)
                    .ok()
                    .and_then(|n| n.try_into().ok())
                    .ok_or_else(|| Error::with_message(Errno::EINVAL, "invalid nice number"))?,
            )),

            // The SCHED_IDLE policy is mapped to the highest nice value of
            // `SchedPolicy::Fair` instead of `SchedPolicy::Idle`. Tasks of the
            // latter policy are invisible to the user API.
            LinuxSchedPolicy::Idle => SchedPolicy::Fair(Nice::MAX),

            LinuxSchedPolicy::Iso | LinuxSchedPolicy::Deadline | LinuxSchedPolicy::Ext => {
                return_errno_with_message!(Errno::EINVAL, "invalid scheduling policy")
            }
        })
    }
}

impl LinuxSchedAttr {
    pub(super) fn user_attr(&self) -> UserSchedAttr {
        let is_fair = matches!(
            LinuxSchedPolicy::try_from(self.sched_policy),
            Ok(LinuxSchedPolicy::Normal | LinuxSchedPolicy::Batch | LinuxSchedPolicy::Idle)
        );

        UserSchedAttr {
            fair_policy: match LinuxSchedPolicy::try_from(self.sched_policy) {
                Ok(LinuxSchedPolicy::Batch) => UserFairPolicy::Batch,
                Ok(LinuxSchedPolicy::Idle) => UserFairPolicy::Idle,
                _ => UserFairPolicy::Normal,
            },
            idle_nice: Nice::default(),
            reset_on_fork: self.sched_flags & SCHED_FLAG_RESET_ON_FORK != 0,
            slice_ns: if is_fair && self.sched_runtime != 0 {
                self.sched_runtime.clamp(MIN_FAIR_SLICE_NS, MAX_FAIR_SLICE_NS)
            } else {
                0
            },
        }
    }

    pub(super) fn with_user_attr(mut self, user: UserSchedAttr) -> Self {
        let is_fair = self.sched_policy == LinuxSchedPolicy::Normal as u32
            || self.sched_policy == LinuxSchedPolicy::Idle as u32;

        if is_fair {
            self.sched_policy = user.fair_policy.linux_policy() as u32;
            if user.fair_policy == UserFairPolicy::Idle {
                self.sched_nice = user.idle_nice.value().get().into();
            }
        }
        if user.reset_on_fork {
            self.sched_flags |= SCHED_FLAG_RESET_ON_FORK;
        }
        if is_fair {
            self.sched_runtime = user.slice_ns;
        }

        self
    }
}

pub(super) fn read_linux_sched_attr_from_user(
    addr: Vaddr,
    ctx: &Context,
) -> Result<LinuxSchedAttr> {
    // The code below is written according to the Linux implementation.
    // Reference: <https://elixir.bootlin.com/linux/v6.17.7/source/kernel/sched/syscalls.c#L889>

    let user_space = ctx.user_space();

    let raw_size = user_space.read_val::<u32>(addr)?;
    let user_size = if raw_size == 0 {
        SCHED_ATTR_SIZE_VER0
    } else {
        raw_size
    };
    if user_size < SCHED_ATTR_SIZE_VER0 || user_size > PAGE_SIZE as u32 {
        let _ = user_space.write_val(addr, &(size_of::<LinuxSchedAttr>() as u32));
        return_errno_with_message!(Errno::E2BIG, "invalid scheduling attribute size");
    }

    let mut attr = user_space
        .read_val_compat::<LinuxSchedAttr>(addr, user_size as usize)
        .inspect_err(|err| {
            if err.error() == Errno::E2BIG {
                let _ = user_space.write_val(addr, &(size_of::<LinuxSchedAttr>() as u32));
            }
        })?;
    // If `attr.size` is modified concurrently, we should use the original size.
    attr.size = user_size;

    // TODO: Check whether `sched_flags` is valid.

    Ok(attr)
}

pub(super) fn write_linux_sched_attr_to_user(
    mut attr: LinuxSchedAttr,
    addr: Vaddr,
    user_size: u32,
    ctx: &Context,
) -> Result<()> {
    if user_size < SCHED_ATTR_SIZE_VER0 || user_size > PAGE_SIZE as u32 {
        return_errno_with_message!(Errno::EINVAL, "invalid scheduling attribute size");
    }

    attr.size = (size_of::<LinuxSchedAttr>() as u32).min(user_size);

    let linux_policy = LinuxSchedPolicy::try_from(attr.sched_policy)
        .expect("all user-visible scheduling policies should be valid");
    let range = sched_priority_range(linux_policy);
    attr.sched_util_min = *range.start();
    attr.sched_util_max = *range.end();

    ctx.user_space()
        .write_val_compat(addr, user_size as usize, &attr)?
        .ignore_trailing();

    Ok(())
}

pub(super) fn access_sched_attr_with<T>(
    tid: Tid,
    ctx: &Context,
    f: impl FnOnce(&SchedAttr) -> Result<T>,
) -> Result<T> {
    if tid.cast_signed() < 0 {
        return_errno_with_message!(Errno::EINVAL, "all negative TIDs are not valid");
    }

    if tid == 0 {
        return f(ctx.thread.sched_attr());
    }

    let Some(thread) = pid_table::pid_table_mut().get_thread(tid) else {
        return_errno_with_message!(Errno::ESRCH, "the target thread does not exist");
    };
    f(thread.sched_attr())
}

pub(super) enum SchedChange {
    Attribute(LinuxSchedAttr),
    Policy(LinuxSchedAttr),
    Priority(u32),
}

pub(super) fn change_sched_attr(tid: Tid, ctx: &Context, change: SchedChange) -> Result<()> {
    if tid.cast_signed() < 0 {
        return_errno_with_message!(Errno::EINVAL, "all negative TIDs are not valid");
    }
    if tid == 0 {
        return change_thread_sched_attr(ctx.thread, ctx, change);
    }
    let Some(thread) = pid_table::pid_table_mut().get_thread(tid) else {
        return_errno_with_message!(Errno::ESRCH, "the target thread does not exist");
    };
    change_thread_sched_attr(&thread, ctx, change)
}

fn change_thread_sched_attr(thread: &Thread, ctx: &Context, change: SchedChange) -> Result<()> {
    let Some(target) = thread.as_posix_thread() else {
        return_errno_with_message!(Errno::ESRCH, "the target is not a userspace thread");
    };
    let target_process = target.process();
    let same_owner = {
        let caller = ctx.posix_thread.credentials();
        let target = target.credentials();
        caller.euid() == target.euid() || caller.euid() == target.ruid()
    };
    let privileged = lsm_hooks::on_capable(lsm_hooks::CapableContext::new(
        UserNamespace::get_init_singleton().as_ref(),
        ctx.posix_thread,
        CapSet::SYS_NICE,
    )).is_ok();
    let limits = target_process.resource_limits();
    let nice_limit = limits.get_rlimit(ResourceType::RLIMIT_NICE).get_cur();
    let rt_limit = limits.get_rlimit(ResourceType::RLIMIT_RTPRIO).get_cur();
    thread.sched_attr().update_user_policy(|old_policy, old_user| {
        let old = LinuxSchedAttr::try_from(old_policy)?.with_user_attr(old_user);
        let (requested, legacy) = match change {
            SchedChange::Attribute(attr) => (attr, false),
            SchedChange::Policy(mut attr) => {
                attr.sched_nice = old.sched_nice;
                (attr, true)
            }
            SchedChange::Priority(priority) => {
                let mut attr = old;
                attr.sched_priority = priority;
                (attr, true)
            }
        };
        if requested.sched_flags & !SCHED_FLAG_RESET_ON_FORK != 0 {
            return_errno_with_message!(Errno::EINVAL, "unsupported scheduling flags");
        }
        let policy = SchedPolicy::try_from(requested)?;
        let mut user = requested.user_attr();
        if legacy {
            user.slice_ns = old_user.slice_ns;
        }
        if user.fair_policy == UserFairPolicy::Idle {
            user.idle_nice = if old_user.fair_policy == UserFairPolicy::Idle {
                old_user.idle_nice
            } else {
                i8::try_from(old.sched_nice).ok().and_then(|nice| nice.try_into().ok()).unwrap_or_default()
            };
        }
        if !privileged {
            let rt = matches!(policy, SchedPolicy::RealTime { .. });
            let old_rt = matches!(old_policy, SchedPolicy::RealTime { .. });
            let raise_nice = matches!(requested.sched_policy, 0 | 3)
                && requested.sched_nice < old.sched_nice
                && (20 - i64::from(requested.sched_nice)) as u64 > nice_limit;
            let leave_idle = old_user.fair_policy == UserFairPolicy::Idle
                && user.fair_policy != UserFairPolicy::Idle
                && (20 - i64::from(old.sched_nice)) as u64 > nice_limit;
            let raise_rt = rt && ((!old_rt || requested.sched_policy != old.sched_policy) && rt_limit == 0
                || requested.sched_priority > old.sched_priority && u64::from(requested.sched_priority) > rt_limit);
            if !same_owner || raise_nice || leave_idle || raise_rt
                || old_user.reset_on_fork && !user.reset_on_fork
            {
                return_errno_with_message!(Errno::EPERM, "scheduling change requires permission");
            }
        }
        Ok((policy, user, ()))
    })
}

pub(super) fn sys_sched_getattr(
    tid: Tid,
    addr: Vaddr,
    user_size: u32,
    flags: u32,
    ctx: &Context,
) -> Result<SyscallReturn> {
    if addr == 0 {
        return_errno_with_message!(Errno::EINVAL, "invalid user space address");
    }
    if flags != 0 {
        // Linux also has no support for any flags yet.
        return_errno_with_message!(Errno::EINVAL, "invalid flags");
    }

    let (policy, user) = access_sched_attr_with(tid, ctx, |attr| Ok(attr.user_policy()))?;
    let attr: LinuxSchedAttr = LinuxSchedAttr::try_from(policy)
        .expect("all user-visible scheduling attributes should be valid")
        .with_user_attr(user);
    write_linux_sched_attr_to_user(attr, addr, user_size, ctx)?;

    Ok(SyscallReturn::Return(0))
}
