// SPDX-License-Identifier: AGPL-3.0-or-later

//! The group and Blockparty services with their warm routing caches. Built
//! only on the roles that read them (front routing, API endpoints); the other
//! roles hold no instance, so no caller there can read a cache nobody filled.

use std::sync::Arc;

use bp_blockparty_engine::BlockpartyService;

use crate::blockparty_service::SharedBlockparty;
use crate::group_service::SharedGroupService;

pub(crate) struct Membership {
    pub(crate) group: SharedGroupService,
    /// `None` unless Blockparty is configured.
    pub(crate) blockparty: Option<SharedBlockparty>,
}

impl Membership {
    pub(crate) fn blockparty_service(&self) -> Option<Arc<BlockpartyService>> {
        self.blockparty.as_ref().map(|bp| bp.service.clone())
    }
}
