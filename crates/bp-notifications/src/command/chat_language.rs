// SPDX-License-Identifier: AGPL-3.0-or-later

//! The reply language of each Telegram chat, stored in
//! `telegram_chat_language` and cached in memory. A chat that never picked
//! one gets the language its Telegram client reports on first contact, if
//! the bot speaks it, else the default.

use std::collections::HashMap;
use std::sync::Arc;

use bp_db::{
    find_telegram_chat_language, insert_telegram_chat_language_if_absent,
    upsert_telegram_chat_language, DbError,
};
use sqlx::PgPool;
use tokio::sync::Mutex;
use tracing::warn;

use crate::format::Language;

#[derive(Clone)]
pub struct ChatLanguages {
    pool: PgPool,
    /// `None`: the chat has no stored language.
    cache: Arc<Mutex<HashMap<i64, Option<Language>>>>,
}

impl ChatLanguages {
    pub fn new(pool: PgPool) -> Self {
        Self {
            pool,
            cache: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub async fn get(&self, chat_id: i64) -> Language {
        self.stored(chat_id).await.unwrap_or_default()
    }

    /// Store `lang` for the chat.
    pub async fn set(&self, chat_id: i64, lang: Language) -> Result<(), DbError> {
        upsert_telegram_chat_language(&self.pool, chat_id, lang.as_str()).await?;
        self.cache.lock().await.insert(chat_id, Some(lang));
        Ok(())
    }

    /// A chat without a stored language takes the one its client reports
    /// (`language_code`, e.g. `de` or `de-CH`) when the bot speaks it. A
    /// stored language is never replaced here, even when it was not read.
    pub async fn adopt_client_language(&self, chat_id: i64, language_code: &str) {
        let Some(lang) = client_language(language_code) else {
            return;
        };
        if matches!(self.cache.lock().await.get(&chat_id), Some(Some(_))) {
            return;
        }
        match insert_telegram_chat_language_if_absent(&self.pool, chat_id, lang.as_str()).await {
            Ok(true) => {
                self.cache.lock().await.insert(chat_id, Some(lang));
            }
            // Another language is stored: the next read fetches it.
            Ok(false) => {
                self.cache.lock().await.remove(&chat_id);
            }
            Err(e) => {
                warn!(target: "bp_notifications::command", error = %e, chat_id, "store client language");
            }
        }
    }

    /// A failed read is not cached, so the next message tries again.
    async fn stored(&self, chat_id: i64) -> Option<Language> {
        if let Some(cached) = self.cache.lock().await.get(&chat_id) {
            return *cached;
        }
        match find_telegram_chat_language(&self.pool, chat_id).await {
            Ok(row) => {
                let lang = row.as_deref().map(Language::parse);
                self.cache.lock().await.insert(chat_id, lang);
                lang
            }
            Err(e) => {
                warn!(target: "bp_notifications::command", error = %e, chat_id, "read chat language");
                None
            }
        }
    }
}

fn client_language(language_code: &str) -> Option<Language> {
    let primary = language_code.split(['-', '_']).next()?.to_ascii_lowercase();
    match primary.as_str() {
        "de" => Some(Language::De),
        "en" => Some(Language::En),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_client_language_the_bot_speaks_is_taken() {
        assert_eq!(client_language("de"), Some(Language::De));
        assert_eq!(client_language("de-CH"), Some(Language::De));
        assert_eq!(client_language("EN-us"), Some(Language::En));
        assert_eq!(client_language("fr"), None);
        assert_eq!(client_language(""), None);
    }

    async fn forget(pool: &PgPool, chat_id: i64) {
        sqlx::query(r#"DELETE FROM telegram_chat_language WHERE "telegramChatId" = $1"#)
            .bind(chat_id)
            .execute(pool)
            .await
            .unwrap();
    }

    /// A picked language survives a restart (a fresh instance), and the
    /// client's language fills in only where the chat picked none.
    #[tokio::test]
    async fn a_picked_language_outlives_the_process() {
        let Some(pool) = bp_test_support::connect_pg_or_skip().await else {
            return;
        };
        let (picked, fresh, foreign) = (-7_700_001, -7_700_002, -7_700_003);
        for chat in [picked, fresh, foreign] {
            forget(&pool, chat).await;
        }
        let before = ChatLanguages::new(pool.clone());
        before.set(picked, Language::De).await.unwrap();
        // The client says English: a picked language stays.
        before.adopt_client_language(picked, "en").await;
        before.adopt_client_language(fresh, "de-AT").await;
        before.adopt_client_language(foreign, "fr").await;

        // A cold cache does not let the client language replace a pick.
        let cold = ChatLanguages::new(pool.clone());
        cold.adopt_client_language(picked, "en").await;

        let after = ChatLanguages::new(pool.clone());
        assert_eq!(after.get(picked).await, Language::De);
        assert_eq!(after.get(fresh).await, Language::De);
        assert_eq!(after.get(foreign).await, Language::default());

        for chat in [picked, fresh, foreign] {
            forget(&pool, chat).await;
        }
    }
}
