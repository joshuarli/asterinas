// SPDX-License-Identifier: MPL-2.0

//! Power management.

mod qemu_isa_debug {
    //! The isa-debug-exit device in QEMU.
    //!
    //! Reference: <https://elixir.bootlin.com/qemu/v10.1.2/source/hw/misc/debugexit.c>

    use spin::Once;

    use crate::{arch::device::io_port::WriteOnlyAccess, io::IoPort, power::ExitCode};

    // For `qemu-system-x86_64`, the exit code will be `(code << 1) | 1`. So it is not possible to
    // let QEMU invoke `exit(0)`. We also need to check if the exit code is returned by the kernel,
    // so we cannot use `0` as `EXIT_SUCCESS` because it may conflict with QEMU's return value `1`,
    // which indicates that QEMU itself fails.
    const EXIT_SUCCESS: u32 = 0x10;
    const EXIT_FAILURE: u32 = 0x20;

    static DEBUG_EXIT_PORT: Once<IoPort<u32, WriteOnlyAccess>> = Once::new();

    pub(super) fn try_exit_qemu(code: ExitCode) {
        let value = match code {
            ExitCode::Success => EXIT_SUCCESS,
            ExitCode::Failure => EXIT_FAILURE,
        };

        // If possible, keep this method panic-free because it may be called by the panic handler.
        if let Some(port) = DEBUG_EXIT_PORT.get() {
            port.write(value);
        }
    }

    pub(super) fn init() {
        const DEBUG_EXIT_PORT_NUM: u16 = 0xF4;

        let debug_exit_port = IoPort::acquire(DEBUG_EXIT_PORT_NUM).unwrap();

        DEBUG_EXIT_PORT.call_once(|| debug_exit_port);
    }
}

mod qemu_acpi {
    //! The ACPI power management registers that QEMU's q35 machine provides.
    //!
    //! Reference: <https://elixir.bootlin.com/qemu/v10.1.2/source/hw/acpi/core.c>

    use crate::arch::device::io_port::PortWrite;

    const PM1A_CONTROL_PORT: u16 = 0x604;
    const SLEEP_ENABLE_SOFT_OFF: u16 = 1 << 13;

    pub(super) fn try_power_off() {
        // SAFETY: Writing the soft-off request to the PM1a control register of QEMU powers the
        // machine off. On other platforms, this port is either unassigned or part of a device
        // that treats the write as a request to leave the running state; the system is being
        // shut down, so no kernel memory is at stake.
        unsafe { PortWrite::write_to_port(PM1A_CONTROL_PORT, SLEEP_ENABLE_SOFT_OFF) };
    }
}

mod keyboard_controller {
    //! The reset line of the legacy keyboard controller.
    //!
    //! Firecracker has no ACPI power management. It ends the VM, and exits, when the guest asks the
    //! emulated i8042 controller to reset the CPU.
    //!
    //! Reference: <https://github.com/firecracker-microvm/firecracker/blob/v1.17.0/src/vmm/src/devices/legacy/i8042.rs>

    use crate::arch::device::io_port::PortWrite;

    const COMMAND_PORT: u16 = 0x64;
    const COMMAND_RESET_CPU: u8 = 0xFE;

    pub(super) fn try_reset() {
        // SAFETY: Resetting the CPU does not touch kernel memory; the system is being shut down.
        unsafe { PortWrite::write_to_port(COMMAND_PORT, COMMAND_RESET_CPU) };
    }
}

pub(super) fn init() {
    use super::cpu::cpuid;

    if !cpuid::query_if_running_in_qemu() {
        return;
    }

    // FIXME: We assume that the kernel is running in QEMU with the following QEMU command line
    // arguments that specify the isa-debug-exit device:
    // `-device isa-debug-exit,iobase=0xf4,iosize=0x04`.
    crate::info!("QEMU hypervisor detected, assuming that the isa-debug-exit device exists");

    qemu_isa_debug::init();
}

/// Attempts to power off the system using an architecture-specific mechanism.
///
/// On x86, this function first tries QEMU's ISA debug-exit device if QEMU was detected during
/// initialization, so that the exit code reaches QEMU. A hypervisor that identifies itself as KVM
/// or QEMU then gets the ACPI soft-off request of the q35 machine and, for VMMs without ACPI such
/// as Firecracker, the reset command of the keyboard controller, which ends their VM. Otherwise,
/// it does nothing and returns.
pub fn try_poweroff(code: crate::power::ExitCode) {
    qemu_isa_debug::try_exit_qemu(code);

    if super::cpu::cpuid::query_if_running_in_qemu() {
        qemu_acpi::try_power_off();
        keyboard_controller::try_reset();
    }
}

/// Attempts to restart the system using an architecture-specific mechanism.
///
/// On x86, this function currently does nothing and returns.
pub fn try_restart(_code: crate::power::ExitCode) {
    // TODO: Add an OSTD-level restart mechanism for x86.
}
