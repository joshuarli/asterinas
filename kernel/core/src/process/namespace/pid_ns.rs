// SPDX-License-Identifier: MPL-2.0

use spin::Once;

use crate::{
    fs::pseudofs::{NsCommonOps, NsType, StashedDentry},
    prelude::*,
    process::{Process, UserNamespace},
};

pub(crate) struct PidNamespace {
    stashed_dentry: StashedDentry,
}

impl Process {
    /// Returns the initial PID namespace shared by all processes while
    /// creating and joining other PID namespaces remains unsupported.
    pub(crate) fn pid_ns(&self) -> &'static Arc<PidNamespace> {
        static INIT: Once<Arc<PidNamespace>> = Once::new();
        INIT.call_once(|| {
            Arc::new(PidNamespace {
                stashed_dentry: StashedDentry::new(),
            })
        })
    }
}

impl NsCommonOps for PidNamespace {
    const TYPE: NsType = NsType::Pid;

    fn owner_user_ns(&self) -> Option<&Arc<UserNamespace>> {
        Some(UserNamespace::get_init_singleton())
    }

    fn parent(&self) -> Result<&Arc<Self>> {
        return_errno_with_message!(Errno::EPERM, "the initial PID namespace has no parent");
    }

    fn stashed_dentry(&self) -> &StashedDentry {
        &self.stashed_dentry
    }
}
