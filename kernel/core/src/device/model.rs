// SPDX-License-Identifier: MPL-2.0

//! The kernel side of the device model: the hooks that give the
//! `aster-device` component access to devtmpfs.

use aster_device::{
    common::DevKind,
    hooks::{self, DevNodeRequest, HookError, KernelHooks, UeventOrigin, UeventRequest},
};

use crate::{
    device::DeviceType,
    fs::{
        devtmpfs::{self, DevtmpfsNode, DevtmpfsNodeMeta},
        file::InodeMode,
    },
    prelude::*,
};

/// Installs the kernel hooks. Must run once `devtmpfsd` is running.
pub(super) fn init_in_first_kthread() {
    // The devtmpfs worker is started by `fs::init_in_first_kthread`.
    hooks::install_hooks(&Hooks);
}

struct Hooks;

impl KernelHooks for Hooks {
    fn create_devnode(&self, request: &DevNodeRequest) -> core::result::Result<(), HookError> {
        let node = to_devtmpfs_node(request).map_err(|_| HookError)?;
        devtmpfs::create_node(node).map_err(|error| {
            warn!(
                "failed to create devtmpfs node {:?}: {:?}",
                request.path, error
            );
            HookError
        })
    }

    fn emit_uevent(&self, request: &UeventRequest) -> core::result::Result<(), HookError> {
        let devpath = request.devpath.clone();
        let subsystem = request.subsystem.clone();
        let environment = request.environment.clone();
        match &request.origin {
            UeventOrigin::Written(command) => crate::net::socket::netlink::broadcast_synthetic_uevent(
                command,
                devpath,
                subsystem,
                environment,
            ),
            UeventOrigin::Registered => crate::net::socket::netlink::broadcast_add_uevent(
                devpath,
                subsystem,
                environment,
            ),
        }
        .map_err(|_| HookError)
    }

    fn delete_devnode(&self, request: &DevNodeRequest) -> core::result::Result<(), HookError> {
        let node = to_devtmpfs_node(request).map_err(|_| HookError)?;
        devtmpfs::delete_node(node).map_err(|error| {
            warn!(
                "failed to delete devtmpfs node {:?}: {:?}",
                request.path, error
            );
            HookError
        })
    }
}

fn to_devtmpfs_node(request: &DevNodeRequest) -> Result<DevtmpfsNode> {
    let device_type = match request.devnum.kind() {
        DevKind::Char => DeviceType::Char,
        DevKind::Block => DeviceType::Block,
    };
    let mode = InodeMode::from_bits(request.mode)
        .ok_or_else(|| Error::with_message(Errno::EINVAL, "invalid device node mode"))?;
    let meta = DevtmpfsNodeMeta::with_mode(request.path.clone(), mode)
        .map_err(|_| Error::with_message(Errno::EINVAL, "invalid device node path"))?;
    Ok(DevtmpfsNode::new(device_type, request.devnum.id(), meta))
}
