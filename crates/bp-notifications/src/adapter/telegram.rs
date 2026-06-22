// SPDX-License-Identifier: AGPL-3.0-or-later

//! Telegram Bot adapter — outbound `sendMessage` + the inline-keyboard
//! primitives the bot-command callback flows need (`editMessageText`,
//! `answerCallbackQuery`, and `sendMessage` with a `reply_markup`).

use reqwest::Client;
use serde::{Deserialize, Serialize};
use tracing::warn;

use super::error::{AdapterError, AdapterResult};

/// One inline-keyboard button: a label + the `callback_data` Telegram
/// echoes back in the `callback_query` when the user taps it.
#[derive(Debug, Clone, Serialize)]
pub struct InlineButton {
    pub text: String,
    pub callback_data: String,
}

impl InlineButton {
    pub fn new(text: impl Into<String>, callback_data: impl Into<String>) -> Self {
        Self {
            text: text.into(),
            callback_data: callback_data.into(),
        }
    }
}

/// Rows of inline buttons — the `reply_markup.inline_keyboard` shape.
pub type InlineKeyboard = Vec<Vec<InlineButton>>;

#[derive(Serialize)]
struct ReplyMarkup<'a> {
    inline_keyboard: &'a InlineKeyboard,
}

#[derive(Debug, Clone)]
pub struct TelegramConfig {
    /// Bot token from `@BotFather` — `TELEGRAM_BOT_TOKEN` env var.
    pub bot_token: String,
}

pub struct TelegramAdapter {
    client: Client,
    api_root: String,
}

impl TelegramAdapter {
    pub fn new(config: TelegramConfig) -> AdapterResult<Self> {
        if config.bot_token.trim().is_empty() {
            return Err(AdapterError::Config(
                "TELEGRAM_BOT_TOKEN is empty".to_string(),
            ));
        }
        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .map_err(|e| AdapterError::Config(format!("reqwest client build: {e}")))?;
        let api_root = format!("https://api.telegram.org/bot{}", config.bot_token);
        Ok(Self { client, api_root })
    }

    /// Plain-text `sendMessage`. We deliberately don't use Markdown /
    /// HTML parse_mode on the notification path — every notification
    /// renderer in `format::*` already produces plain text with emoji
    /// (`📶`, `🏆`, `📴`) that Telegram displays without parsing.
    pub async fn send_text(&self, chat_id: i64, text: &str) -> AdapterResult<()> {
        #[derive(Serialize)]
        struct SendMessageBody<'a> {
            chat_id: i64,
            text: &'a str,
        }
        self.post(
            "sendMessage",
            &SendMessageBody { chat_id, text },
            Some(chat_id),
        )
        .await
        .map(|_| ())
    }

    /// `sendMessage` carrying an inline keyboard. Returns the new
    /// message's `message_id` so the caller can later edit it in place
    /// (the callback flows re-render the same message after each tap).
    pub async fn send_message_with_keyboard(
        &self,
        chat_id: i64,
        text: &str,
        keyboard: &InlineKeyboard,
    ) -> AdapterResult<i64> {
        #[derive(Serialize)]
        struct Body<'a> {
            chat_id: i64,
            text: &'a str,
            reply_markup: ReplyMarkup<'a>,
        }
        let body = Body {
            chat_id,
            text,
            reply_markup: ReplyMarkup {
                inline_keyboard: keyboard,
            },
        };
        let resp = self.post("sendMessage", &body, Some(chat_id)).await?;
        #[derive(Deserialize)]
        struct SentResult {
            message_id: i64,
        }
        #[derive(Deserialize)]
        struct SentEnvelope {
            result: SentResult,
        }
        let parsed: SentEnvelope = resp
            .json()
            .await
            .map_err(|e| AdapterError::Server(format!("telegram sendMessage decode: {e}")))?;
        Ok(parsed.result.message_id)
    }

    /// `editMessageText` — re-render an existing message's text and
    /// (optionally) its inline keyboard. Used to refresh a keyboard
    /// after a tap, or to replace it with a final confirmation line.
    pub async fn edit_message_text(
        &self,
        chat_id: i64,
        message_id: i64,
        text: &str,
        keyboard: Option<&InlineKeyboard>,
    ) -> AdapterResult<()> {
        #[derive(Serialize)]
        struct Body<'a> {
            chat_id: i64,
            message_id: i64,
            text: &'a str,
            #[serde(skip_serializing_if = "Option::is_none")]
            reply_markup: Option<ReplyMarkup<'a>>,
        }
        let body = Body {
            chat_id,
            message_id,
            text,
            reply_markup: keyboard.map(|inline_keyboard| ReplyMarkup { inline_keyboard }),
        };
        self.post("editMessageText", &body, Some(chat_id))
            .await
            .map(|_| ())
    }

    /// `answerCallbackQuery` — stops the button's loading spinner and
    /// optionally shows a short toast. Always call it once per tap.
    pub async fn answer_callback_query(
        &self,
        callback_query_id: &str,
        text: Option<&str>,
    ) -> AdapterResult<()> {
        #[derive(Serialize)]
        struct Body<'a> {
            callback_query_id: &'a str,
            #[serde(skip_serializing_if = "Option::is_none")]
            text: Option<&'a str>,
        }
        self.post(
            "answerCallbackQuery",
            &Body {
                callback_query_id,
                text,
            },
            None,
        )
        .await
        .map(|_| ())
    }

    /// POST a JSON body to a Bot API method, mapping HTTP status into
    /// the adapter's error taxonomy. Returns the raw success response
    /// so callers that need the result payload can decode it.
    async fn post(
        &self,
        method: &str,
        body: &impl Serialize,
        chat_id: Option<i64>,
    ) -> AdapterResult<reqwest::Response> {
        let url = format!("{}/{}", self.api_root, method);
        let response = self
            .client
            .post(&url)
            .json(body)
            .send()
            .await
            .map_err(|e| AdapterError::Transport(format!("telegram POST {method}: {e}")))?;

        let status = response.status();
        if status.is_success() {
            return Ok(response);
        }

        // Telegram returns JSON with `ok: false` + `description` +
        // `error_code` on permanent failures. 401 = bad token,
        // 403 = bot blocked by user (permanently invalid chat),
        // 400 = bad request (often "chat not found" — also
        // permanently invalid). Other codes are transient.
        let code = status.as_u16();
        let snippet = response
            .text()
            .await
            .unwrap_or_else(|_| String::from("(body unreadable)"));
        match code {
            401 => Err(AdapterError::Auth(format!("telegram 401: {snippet}"))),
            400 | 403 => {
                warn!(target: "bp_notifications::telegram", ?chat_id, snippet = %snippet, "telegram permanent rejection");
                Err(AdapterError::InvalidRecipient(format!(
                    "telegram {code}: {snippet}"
                )))
            }
            _ => Err(AdapterError::Server(format!("telegram {code}: {snippet}"))),
        }
    }
}
