// SPDX-License-Identifier: AGPL-3.0-or-later

//! An address's payout mode, shared by `/api/pplns/mode/:address` and the
//! block-template preview so the two cannot disagree. The live port marker
//! goes first (a group one only while the group resolves); the state fallback
//! lags by hours after a port switch, since window shares outlive it.

use bp_common::{AddressId, MiningMode};
use bp_mining_mode::MiningModeResult;
use redis::AsyncCommands;

use crate::error::ApiError;
use crate::state::AppState;

pub(crate) async fn resolve_address_mode(
    s: &AppState,
    address: &AddressId,
) -> Result<MiningModeResult, ApiError> {
    let marker = read_live_marker(s, address).await;
    resolve_with_marker(s, address, marker).await
}

/// The live marker, if one is set and names a known mode. A Redis error or
/// an unknown value reads as no marker: the state fallback still answers.
async fn read_live_marker(s: &AppState, address: &AddressId) -> Option<MiningMode> {
    let mut redis = s.redis.clone()?;
    let raw: Option<String> = redis
        .get(format!("miner:{}:mode", address.as_str()))
        .await
        .ok()?;
    raw?.parse().ok()
}

async fn resolve_with_marker(
    s: &AppState,
    address: &AddressId,
    marker: Option<MiningMode>,
) -> Result<MiningModeResult, ApiError> {
    match marker {
        Some(MiningMode::Solo) => return Ok(MiningModeResult::Solo),
        Some(MiningMode::Pplns) => return Ok(MiningModeResult::Pplns),
        Some(MiningMode::GroupSolo) => {
            if let Some(found) = group_solo_group(s, address).await? {
                return Ok(found);
            }
        }
        Some(MiningMode::Blockparty) => {
            if let Some(found) = blockparty_group(s, address).await {
                return Ok(found);
            }
        }
        None => {}
    }

    if let Some(found) = group_solo_group(s, address).await? {
        return Ok(found);
    }
    if let Some(found) = blockparty_group(s, address).await {
        return Ok(found);
    }
    if let Some(engine) = s.pplns.as_ref() {
        if let Ok(Some(status)) = engine.reader().address_status(address.as_str()).await {
            if status.current_window_shares > 0.0 {
                return Ok(MiningModeResult::Pplns);
            }
        }
    }
    Ok(MiningModeResult::Solo)
}

async fn group_solo_group(
    s: &AppState,
    address: &AddressId,
) -> Result<Option<MiningModeResult>, ApiError> {
    Ok(bp_db::find_group_member_by_address(&s.pool, address)
        .await?
        .map(|member| MiningModeResult::GroupSolo(member.group_id)))
}

async fn blockparty_group(s: &AppState, address: &AddressId) -> Option<MiningModeResult> {
    let group_id = s
        .blockparty
        .as_ref()?
        .routable_group_id_for_admin(address)
        .await?;
    Some(MiningModeResult::Blockparty(group_id))
}

#[cfg(test)]
mod tests {
    use super::*;

    // An address no fixture ever writes, so the state fallback finds
    // nothing for it and answers Solo.
    const ADDR: &str = "bcrt1qmodeunittestaddressxxxxxxxxxxxxxxxxxx";

    /// The marker wins over the state fallback (negative control: no marker
    /// reads Solo).
    #[tokio::test]
    async fn the_live_marker_wins_over_the_state_fallback() {
        let Some(pool) = bp_test_support::connect_pg_or_skip().await else {
            return;
        };
        let s = AppState::new(pool, "0.0.0");
        let address = AddressId::new(ADDR).unwrap();

        let with_marker = resolve_with_marker(&s, &address, Some(MiningMode::Pplns))
            .await
            .unwrap();
        assert_eq!(with_marker, MiningModeResult::Pplns);

        let without = resolve_with_marker(&s, &address, None).await.unwrap();
        assert_eq!(
            without,
            MiningModeResult::Solo,
            "precondition: the fallback alone must not already say PPLNS"
        );
    }

    /// A group marker whose group no longer resolves falls through to state.
    #[tokio::test]
    async fn a_group_marker_without_its_group_falls_through() {
        let Some(pool) = bp_test_support::connect_pg_or_skip().await else {
            return;
        };
        let s = AppState::new(pool, "0.0.0");
        let address = AddressId::new(ADDR).unwrap();

        for marker in [MiningMode::GroupSolo, MiningMode::Blockparty] {
            let got = resolve_with_marker(&s, &address, Some(marker))
                .await
                .unwrap();
            assert_eq!(got, MiningModeResult::Solo, "{marker:?}");
        }
    }
}
