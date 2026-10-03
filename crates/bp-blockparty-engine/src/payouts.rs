// SPDX-License-Identifier: AGPL-3.0-or-later

//! The DB-only half of Blockparty: the coinbase split and the block-history
//! row. It carries no routing cache, so every process may hold one.

use bp_blockparty::{
    build_blockparty_distribution, BlockpartyDistributionInput, BlockpartyDistributionResult,
    BlockpartyMemberInput,
};
use bp_common::{now_ms, AddressId};
use bp_db::{BlockpartyBlockHistoryRow, BlockpartySplitSnapshot};
use sqlx::PgPool;
use uuid::Uuid;

use crate::error::BlockpartyServiceError;

/// Fee address and percent are resolved by the boot layer and passed in.
#[derive(Clone, Debug)]
pub struct BlockpartyPayoutConfig {
    pub fee_address: Option<AddressId>,
    pub fee_percent: f64,
    /// Dust floor per member output; clamped to at least
    /// `bp_blockparty::DUST_LIMIT_SATS`.
    pub min_payout_sats: bp_common::Sats,
}

impl Default for BlockpartyPayoutConfig {
    fn default() -> Self {
        Self {
            fee_address: None,
            fee_percent: 2.0,
            min_payout_sats: bp_common::Sats(5_000),
        }
    }
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
        let inputs: Vec<BlockpartyMemberInput<'_>> = members
            .iter()
            .map(|m| BlockpartyMemberInput {
                address: &m.address,
                percent_bp: m.percent_bp,
            })
            .collect();
        let result = build_blockparty_distribution(BlockpartyDistributionInput {
            members: &inputs,
            block_reward_sats,
            pool_fee_address: self.config.fee_address.as_ref(),
            pool_fee_percent: self.config.fee_percent,
            min_payout_sats: self.config.min_payout_sats,
        });
        Ok(Some(result))
    }

    /// Idempotent via UNIQUE(groupId, blockHash): `None` on replay.
    #[allow(clippy::too_many_arguments)]
    pub async fn on_block_found(
        &self,
        group_id: Uuid,
        block_height: i32,
        block_hash: &str,
        coinbase_value_sats: bp_common::Sats,
        pool_fee_sats: bp_common::Sats,
        splits: &[BlockpartySplitSnapshot],
        found_at: Option<i64>,
    ) -> Result<Option<BlockpartyBlockHistoryRow>, BlockpartyServiceError> {
        let now = now_ms();
        let row = bp_db::insert_blockparty_block_history(
            &self.pool,
            group_id,
            block_height,
            block_hash,
            found_at.unwrap_or(now),
            coinbase_value_sats,
            pool_fee_sats,
            splits,
            now,
        )
        .await?;
        Ok(row)
    }
}
