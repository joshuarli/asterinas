// SPDX-License-Identifier: MPL-2.0

//! Device-node creation and deletion through configurable hooks.
//!
//! The device model delegates `/dev` node operations to [`KernelHooks`].
//! Implement this trait in the code that manages the device filesystem,
//! then call [`install_hooks`] once it is ready to create and delete nodes.
//! Node creation requests are queued until [`install_hooks`] installs the hooks and replays them.
//! Each [`DevNodeRequest`] carries the device number, path relative to `/dev`, and permissions.

use alloc::{string::String, vec::Vec};

use ostd::sync::Mutex;
use spin::Once;

use crate::common::{DevNum, Error, Result, SysStr};

/// Installs the kernel hooks and replays every request queued before.
///
/// The hooks must be ready to handle requests when installed.
/// Node creation requests are queued before installation;
/// removing a device cancels its queued request.
/// Calling this a second time has no effect.
pub fn install_hooks(hooks: &'static dyn KernelHooks) {
    HOOKS.install(hooks);
}

/// Callbacks for creating and deleting `/dev` nodes.
///
/// Installed through [`install_hooks`] once the callbacks are ready to handle requests.
/// Until then, node creation requests are queued.
pub trait KernelHooks: Send + Sync + 'static {
    /// Creates a `/dev` node.
    ///
    /// A path with `/` in it, such as `input/event0`,
    /// means the intermediate directories are created too.
    fn create_devnode(&self, request: &DevNodeRequest) -> core::result::Result<(), HookError>;

    /// Deletes a `/dev` node created earlier.
    /// The request is the one that created the node.
    fn delete_devnode(&self, request: &DevNodeRequest) -> core::result::Result<(), HookError>;

    /// Delivers the uevent of a device: the event a write to its `uevent` attribute asks for,
    /// or the `add` event of its registration.
    ///
    /// Fails when the command of a [`UeventOrigin::Written`] request is not a valid synthetic uevent.
    fn emit_uevent(&self, request: &UeventRequest) -> core::result::Result<(), HookError>;
}

/// What caused a uevent.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum UeventOrigin {
    /// A write to the device's `uevent` attribute: an action, an optional token, and `KEY=VALUE` pairs.
    Written(String),
    /// The registration of the device.
    Registered,
}

/// A request to deliver a uevent for a device.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UeventRequest {
    /// What caused the event.
    pub origin: UeventOrigin,
    /// The device's absolute path under sysfs, such as `/devices/virtual/block/vda`.
    pub devpath: String,
    /// The name of the subsystem that owns the device.
    pub subsystem: String,
    /// The `MAJOR`, `MINOR`, `DEVNAME` and `DEVTYPE` values the device contributes.
    pub environment: Vec<(String, String)>,
}

/// A request to create or delete a `/dev` node.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DevNodeRequest {
    /// The device number the node refers to.
    pub devnum: DevNum,
    /// The path of the node relative to `/dev`, e.g. `null` or `input/event0`.
    pub path: SysStr,
    /// The permission bits of the node.
    pub mode: u16,
}

/// An error from a kernel hook.
#[derive(Clone, Copy, Debug)]
pub struct HookError;

pub(crate) fn create_devnode(request: DevNodeRequest) -> Result<()> {
    HOOKS.create_devnode(request)
}

pub(crate) fn delete_devnode(request: &DevNodeRequest) -> Result<()> {
    HOOKS.delete_devnode(request)
}

pub(crate) fn emit_uevent(request: &UeventRequest) -> Result<()> {
    HOOKS.emit_uevent(request)
}

/// Announces a registered device to the listeners of kernel uevents, if the hooks are installed.
///
/// Before the hooks exist nothing can listen, so there is nobody to announce to.
pub(crate) fn announce_registered(request: &UeventRequest) -> Result<()> {
    HOOKS.announce_registered(request)
}

/// The hooks, once installed, and the requests waiting for them.
pub(crate) struct HookSlot {
    hooks: Once<&'static dyn KernelHooks>,
    pending: Mutex<Vec<DevNodeRequest>>,
}

impl HookSlot {
    pub(crate) const fn new() -> Self {
        Self {
            hooks: Once::new(),
            pending: Mutex::new(Vec::new()),
        }
    }

    /// Installs the hooks and replays every request queued before.
    ///
    /// Installing, draining and replaying all happen under the queue lock,
    /// so a request made concurrently is either replayed here or delivered directly,
    /// and a removal cannot overtake the create it cancels.
    /// Calling this a second time has no effect.
    pub(crate) fn install(&self, hooks: &'static dyn KernelHooks) {
        let mut pending = self.pending.lock();
        let installed = self.hooks.call_once(|| hooks);
        for request in core::mem::take(&mut *pending) {
            // A failure here cannot be reported to the caller that queued
            // the request long ago; the node is simply absent.
            let _ = installed.create_devnode(&request);
        }
    }

    pub(crate) fn create_devnode(&self, request: DevNodeRequest) -> Result<()> {
        let mut queue = self.pending.lock();
        match self.hooks.get() {
            Some(hooks) => {
                drop(queue);
                hooks.create_devnode(&request).map_err(|_| Error::Hook)
            }
            None => {
                queue.push(request);
                Ok(())
            }
        }
    }

    pub(crate) fn emit_uevent(&self, request: &UeventRequest) -> Result<()> {
        match self.hooks.get() {
            Some(hooks) => hooks.emit_uevent(request).map_err(|_| Error::InvalidValue),
            None => Err(Error::Hook),
        }
    }

    pub(crate) fn announce_registered(&self, request: &UeventRequest) -> Result<()> {
        match self.hooks.get() {
            Some(hooks) => hooks.emit_uevent(request).map_err(|_| Error::Hook),
            None => Ok(()),
        }
    }

    pub(crate) fn delete_devnode(&self, request: &DevNodeRequest) -> Result<()> {
        let mut queue = self.pending.lock();
        match self.hooks.get() {
            Some(hooks) => {
                drop(queue);
                hooks.delete_devnode(request).map_err(|_| Error::Hook)
            }
            None => {
                // The node was never created; forget the queued request.
                queue.retain(|pending| pending != request);
                Ok(())
            }
        }
    }
}

/// The shared hook slot.
static HOOKS: HookSlot = HookSlot::new();
