// SPDX-License-Identifier: AGPL-3.0-or-later

//! The DB-only half of Blockparty: the coinbase split and the block-history
//! row. It carries no routing cache, so every process may hold one.

use std::collections::HashMap;

use bp_blockparty::{
    build_blockparty_distribution, splits_paid, BlockpartyDistributionInput,
    BlockpartyDistributionResult, BlockpartyMemberInput,
};
use bp_common::{now_ms, AddressId};
use bp_db::{BlockpartyBlockHistoryRow, BlockpartyMemberRow};
use sqlx::PgPool;
use uuid::Uuid;

use crate::error::BlockpartyServiceError;

/// The `[blockparty]` fee settings, validated by the boot layer
/// (`validate_fee_payout_budget`) and passed in.
#[derive(Clone, Debug)]
pub struct BlockpartyPayoutConfig {
    pub fee_address: AddressId,
    pub fee_percent: f64,
    /// Smallest member output, at least `DUST_LIMIT_SATS`.
    pub min_payout_sats: bp_common::Sats,
}

#[derive(Clone)]
pub struct BlockpartyPayouts {
    pub(crate) pool: PgPool,
    pub(crate) config: BlockpartyPayoutConfig,
}

impl BlockpartyPayouts {
    pub fn new(pool: PgPool, config: BlockpartyPayoutConfig) -> Self {
        Self { pool, config }
    }

    /// The pool fee every Blockparty coinbase pays, in percent.
    pub fn fee_percent(&self) -> f64 {
        self.config.fee_percent
    }

    /// Coinbase distribution over the current roster; `Ok(None)` when the
    /// group does not exist.
    pub async fn build_payouts(
        &self,
        group_id: Uuid,
        block_reward_sats: bp_common::Sats,
    ) -> Result<Option<BlockpartyDistributionResult>, BlockpartyServiceError> {
        if bp_db::find_blockparty_group(&self.pool, group_id)
            .await?
            .is_none()
        {
            return Ok(None);
        }
        let members = bp_db::list_blockparty_members_for_group(&self.pool, group_id).await?;
        let result = build_blockparty_distribution(BlockpartyDistributionInput {
            members: &member_inputs(&members),
            block_reward_sats,
            pool_fee_address: &self.config.fee_address,
            pool_fee_percent: self.config.fee_percent,
            min_payout_sats: self.config.min_payout_sats,
        });
        Ok(Some(result))
    }

    /// Book a found block from its own coinbase: each member's sats as
    /// `paid_to` (what the coinbase paid each address) reports them, the pool
    /// fee as the rest of `coinbase_value_sats`. The roster cannot change
    /// while the party is routable, so it is the one the coinbase was built
    /// from. Idempotent via UNIQUE(groupId, blockHash): `None` on replay;
    /// [`BlockpartyServiceError::NotFound`] when the group row does not exist.
    pub async fn on_block_found(
        &self,
        group_id: Uuid,
        block_height: i32,
        block_hash: &str,
        coinbase_value_sats: bp_common::Sats,
        paid_to: &HashMap<String, u64>,
        found_at: Option<i64>,
    ) -> Result<Option<BlockpartyBlockHistoryRow>, BlockpartyServiceError> {
        if bp_db::find_blockparty_group(&self.pool, group_id)
            .await?
            .is_none()
        {
            return Err(BlockpartyServiceError::NotFound);
        }
        let members = bp_db::list_blockparty_members_for_group(&self.pool, group_id).await?;
        let splits = splits_paid(&member_inputs(&members), |address| {
            paid_to.get(address.as_str()).copied().unwrap_or(0)
        });
        let members_paid: i64 = splits.iter().map(|s| s.sats).sum();
        let pool_fee_sats = bp_common::Sats(coinbase_value_sats.0 - members_paid);
        let now = now_ms();
        let row = bp_db::insert_blockparty_block_history(
            &self.pool,
            group_id,
            block_height,
            block_hash,
            found_at.unwrap_or(now),
            coinbase_value_sats,
            pool_fee_sats,
            &splits,
            now,
        )
        .await?;
        Ok(row)
    }
}

fn member_inputs(members: &[BlockpartyMemberRow]) -> Vec<BlockpartyMemberInput<'_>> {
    members
        .iter()
        .map(|m| BlockpartyMemberInput {
            address: &m.address,
            percent_bp: m.percent_bp,
        })
        .collect()
}
