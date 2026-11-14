// SPDX-License-Identifier: MPL-2.0

use spin::Once;

use crate::{
    fs::pseudofs::{NsCommonOps, NsType, StashedDentry},
    prelude::*,
    process::UserNamespace,
};

pub(crate) struct NetNamespace {
    stashed_dentry: StashedDentry,
}

impl NetNamespace {
    pub(crate) fn get_init_singleton() -> &'static Arc<Self> {
        static INIT: Once<Arc<NetNamespace>> = Once::new();
        INIT.call_once(|| {
            Arc::new(Self {
                stashed_dentry: StashedDentry::new(),
            })
        })
    }
}

impl NsCommonOps for NetNamespace {
    const TYPE: NsType = NsType::Net;

    fn owner_user_ns(&self) -> Option<&Arc<UserNamespace>> {
        Some(UserNamespace::get_init_singleton())
    }

    fn parent(&self) -> Result<&Arc<Self>> {
        return_errno_with_message!(Errno::EINVAL, "a network namespace does not have a parent namespace");
    }

    fn stashed_dentry(&self) -> &StashedDentry {
        &self.stashed_dentry
    }
}
