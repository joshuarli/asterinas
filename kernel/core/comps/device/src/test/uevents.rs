// SPDX-License-Identifier: MPL-2.0

//! Tests of the uevents that device registration announces.

use alloc::{string::String, vec::Vec};

use device_id::{DeviceId, MajorId, MinorId};
use ostd::{prelude::ktest, sync::Mutex};

use super::toy::{self, ToyDisk};
use crate::{
    class::ClassDevice,
    common::{BareDevice, DevNum},
    hooks::{self, DevNodeRequest, HookError, KernelHooks, UeventOrigin, UeventRequest},
};

struct Recorder {
    requests: Mutex<Vec<UeventRequest>>,
}

impl KernelHooks for Recorder {
    fn create_devnode(&self, _request: &DevNodeRequest) -> Result<(), HookError> {
        Ok(())
    }

    fn delete_devnode(&self, _request: &DevNodeRequest) -> Result<(), HookError> {
        Ok(())
    }

    fn emit_uevent(&self, request: &UeventRequest) -> Result<(), HookError> {
        self.requests.lock().push(request.clone());
        Ok(())
    }
}

static RECORDER: Recorder = Recorder {
    requests: Mutex::new(Vec::new()),
};

fn announced() -> Vec<UeventRequest> {
    hooks::install_hooks(&RECORDER);
    RECORDER.requests.lock().clone()
}

fn announced_paths() -> Vec<String> {
    announced().into_iter().map(|request| request.devpath).collect()
}

#[ktest]
fn registering_a_device_announces_its_addition() {
    let (class, _) = toy::register_toy_subsystems();
    announced();
    let disk = ClassDevice::builder(&class, "ann0", ToyDisk { sectors: 9 })
        .devnum(DevNum::block(DeviceId::new(
            MajorId::new(7),
            MinorId::new(32),
        )))
        .build();
    crate::add_device(&disk).unwrap();

    let request = announced()
        .into_iter()
        .find(|request| request.devpath == "/devices/virtual/toyblk/ann0")
        .unwrap();
    assert_eq!(request.origin, UeventOrigin::Registered);
    assert_eq!(request.subsystem, "toyblk");
    assert_eq!(
        request.environment,
        [
            (String::from("MAJOR"), String::from("7")),
            (String::from("MINOR"), String::from("32")),
            (String::from("DEVNAME"), String::from("ann0")),
            (String::from("DEVMODE"), String::from("0660")),
            (String::from("TOYSECTORS"), String::from("9")),
        ]
    );

    crate::remove_device(&disk).unwrap();
}

#[ktest]
fn a_parent_is_announced_before_its_children() {
    let (class, _) = toy::register_toy_subsystems();
    announced();
    let disk = ClassDevice::builder(&class, "ann1", ToyDisk { sectors: 16 }).build();
    crate::add_device(&disk).unwrap();
    let part = ClassDevice::builder(&class, "ann1p1", ToyDisk { sectors: 8 })
        .parent(disk.clone())
        .build();
    crate::add_device(&part).unwrap();

    let paths = announced_paths();
    let disk_index = paths.iter().position(|path| path == "/devices/virtual/toyblk/ann1");
    let part_index = paths
        .iter()
        .position(|path| path == "/devices/virtual/toyblk/ann1/ann1p1");
    assert!(disk_index.unwrap() < part_index.unwrap());

    crate::remove_device(&part).unwrap();
    crate::remove_device(&disk).unwrap();
}

#[ktest]
fn a_device_without_a_subsystem_announces_nothing() {
    announced();
    let bridge = BareDevice::new_root("ann-bridge");
    crate::add_device(&bridge).unwrap();

    assert!(!announced_paths().iter().any(|path| path == "/devices/ann-bridge"));

    crate::remove_device(&bridge).unwrap();
}

#[ktest]
fn a_failed_registration_announces_nothing() {
    let (class, _) = toy::register_toy_subsystems();
    announced();
    let orphan_parent = ClassDevice::builder(&class, "ann-parent", ToyDisk { sectors: 0 }).build();
    let orphan = ClassDevice::builder(&class, "ann-orphan", ToyDisk { sectors: 0 })
        .parent(orphan_parent)
        .build();
    assert!(crate::add_device(&orphan).is_err());

    assert!(!announced_paths().iter().any(|path| path.ends_with("ann-orphan")));
}

