// SPDX-License-Identifier: AGPL-3.0-or-later

//! Every Team's and Blockparty's coinbase tag, by group id, as the payout
//! resolver adds it to a job. Warmed at boot and rebuilt with the group and
//! Blockparty routing caches (`cache_sync`), so a job costs no database read.

use std::collections::HashMap;
use std::sync::RwLock;

use bp_common::CoinbaseTag;
use bp_db::DbError;
use sqlx::PgPool;
use uuid::Uuid;

pub(crate) struct CoinbaseTagCache {
    tags: RwLock<HashMap<Uuid, CoinbaseTag>>,
}

impl CoinbaseTagCache {
    pub(crate) async fn load(pool: &PgPool) -> Result<Self, DbError> {
        let cache = Self {
            tags: RwLock::new(HashMap::new()),
        };
        cache.rebuild(pool).await?;
        Ok(cache)
    }

    /// Swap in the tags as the database holds them now.
    pub(crate) async fn rebuild(&self, pool: &PgPool) -> Result<(), DbError> {
        // The column's CHECK admits only what `CoinbaseTag::parse` accepts.
        let tags = bp_db::list_group_coinbase_tags(pool)
            .await?
            .into_iter()
            .filter_map(|(group_id, tag)| {
                CoinbaseTag::parse(&tag)
                    .ok()
                    .flatten()
                    .map(|tag| (group_id, tag))
            })
            .collect();
        *self.tags.write().expect("coinbase tag cache poisoned") = tags;
        Ok(())
    }

    pub(crate) fn get(&self, group_id: Uuid) -> Option<CoinbaseTag> {
        self.tags
            .read()
            .expect("coinbase tag cache poisoned")
            .get(&group_id)
            .cloned()
    }
}

#[cfg(test)]
impl CoinbaseTagCache {
    pub(crate) fn from_tags(tags: impl IntoIterator<Item = (Uuid, CoinbaseTag)>) -> Self {
        Self {
            tags: RwLock::new(tags.into_iter().collect()),
        }
    }
}

#[cfg(test)]
mod tests {
    use bp_common::AddressId;

    use super::*;

    fn address(tag: &str) -> AddressId {
        AddressId::new(format!("bcrt1q{tag}{}", Uuid::new_v4().simple())).unwrap()
    }

    /// A Team's and a Blockparty's tags load by group id; an untagged group
    /// and a dissolved one have none, and a cleared tag is gone on rebuild.
    #[tokio::test]
    async fn the_cache_holds_the_tags_of_live_teams_and_blockpartys() {
        let Some(pool) = bp_test_support::connect_pg_or_skip().await else {
            return;
        };
        let (team, party, untagged, dissolved) = (
            Uuid::new_v4(),
            Uuid::new_v4(),
            Uuid::new_v4(),
            Uuid::new_v4(),
        );
        for id in [team, untagged, dissolved] {
            bp_db::insert_pplns_group(
                &pool,
                id,
                &format!("tag-test-{id}"),
                &address("team"),
                "h",
                true,
                false,
                "prop",
                1,
            )
            .await
            .unwrap();
        }
        bp_db::insert_blockparty_group(
            &pool,
            party,
            &format!("tag-test-{party}"),
            &address("party"),
            "h",
            "ACTIVE",
            1,
        )
        .await
        .unwrap();
        let set_team_tag = |id: Uuid, tag: Option<&str>| {
            let pool = pool.clone();
            let patch = bp_db::RoundResetConfigPatch {
                coinbase_tag: match tag {
                    Some(t) => bp_db::PatchField::Set(t.to_string()),
                    None => bp_db::PatchField::Clear,
                },
                ..bp_db::RoundResetConfigPatch::default()
            };
            async move {
                bp_db::update_pplns_group_round_reset_config(&pool, id, &patch, 2)
                    .await
                    .unwrap()
                    .unwrap();
            }
        };
        set_team_tag(team, Some("Dezentralschweiz")).await;
        set_team_tag(dissolved, Some("Gone")).await;
        bp_db::update_pplns_group_dissolved(&pool, dissolved, 3)
            .await
            .unwrap();
        bp_db::update_blockparty_group_coinbase_tag(&pool, party, Some("Party CH"), 2)
            .await
            .unwrap();

        let cache = CoinbaseTagCache::load(&pool).await.unwrap();
        let tag = |id| cache.get(id).map(|t| t.as_str().to_string());
        assert_eq!(tag(team).as_deref(), Some("Dezentralschweiz"));
        assert_eq!(tag(party).as_deref(), Some("Party CH"));
        assert_eq!(tag(untagged), None);
        assert_eq!(tag(dissolved), None, "a dissolved group tags nothing");

        set_team_tag(team, None).await;
        cache.rebuild(&pool).await.unwrap();
        assert_eq!(tag(team), None, "a cleared tag is gone after a rebuild");

        for id in [team, untagged, dissolved] {
            sqlx::query("DELETE FROM pplns_group WHERE id = $1")
                .bind(id)
                .execute(&pool)
                .await
                .ok();
        }
        sqlx::query("DELETE FROM blockparty_group WHERE id = $1")
            .bind(party)
            .execute(&pool)
            .await
            .ok();
    }
}
