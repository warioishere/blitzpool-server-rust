// SPDX-License-Identifier: AGPL-3.0-or-later

//! Telegram Bot adapter — outbound `sendMessage` + the inline-keyboard
//! primitives the bot-command callback flows need (`editMessageText`,
//! `answerCallbackQuery`, and `sendMessage` with a `reply_markup`).

use reqwest::Client;
use serde::{Deserialize, Serialize};

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

/// The bot's messages show links without a preview card; the links stay
/// clickable.
#[derive(Serialize, Clone, Copy)]
struct LinkPreviewOptions {
    is_disabled: bool,
}

const NO_PREVIEW: LinkPreviewOptions = LinkPreviewOptions { is_disabled: true };

/// Every message text and edit is Telegram HTML.
const PARSE_MODE: &str = "HTML";

/// Opens the reply field on the message, so the user answers it directly.
#[derive(Serialize)]
struct ForceReply<'a> {
    force_reply: bool,
    input_field_placeholder: &'a str,
}

#[derive(Debug, Clone)]
pub struct TelegramConfig {
    /// Bot token from `@BotFather` — `[notifications.telegram] bot_token`.
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
                "[notifications.telegram] bot_token is empty".to_string(),
            ));
        }
        let client = bp_http::client_builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .map_err(|e| AdapterError::Config(format!("reqwest client build: {e}")))?;
        let api_root = format!("https://api.telegram.org/bot{}", config.bot_token);
        Ok(Self { client, api_root })
    }

    /// `sendMessage` of a bot message, Telegram HTML
    /// ([`crate::format::html`]).
    pub async fn send_html(&self, chat_id: i64, html: &str) -> AdapterResult<()> {
        #[derive(Serialize)]
        struct SendMessageBody<'a> {
            chat_id: i64,
            text: &'a str,
            parse_mode: &'static str,
            link_preview_options: LinkPreviewOptions,
        }
        let body = SendMessageBody {
            chat_id,
            text: html,
            parse_mode: PARSE_MODE,
            link_preview_options: NO_PREVIEW,
        };
        self.post("sendMessage", &body).await.map(|_| ())
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
        let markup = ReplyMarkup {
            inline_keyboard: keyboard,
        };
        self.send_message_with_markup(chat_id, text, &markup).await
    }

    /// A question the user answers in the reply field, `placeholder`
    /// shown in it. Returns the question's `message_id`, which the answer
    /// carries as `reply_to_message`.
    pub async fn send_question(
        &self,
        chat_id: i64,
        text: &str,
        placeholder: &str,
    ) -> AdapterResult<i64> {
        let markup = ForceReply {
            force_reply: true,
            input_field_placeholder: placeholder,
        };
        self.send_message_with_markup(chat_id, text, &markup).await
    }

    async fn send_message_with_markup(
        &self,
        chat_id: i64,
        text: &str,
        reply_markup: &impl Serialize,
    ) -> AdapterResult<i64> {
        #[derive(Serialize)]
        struct Body<'a, M: Serialize> {
            chat_id: i64,
            text: &'a str,
            parse_mode: &'static str,
            reply_markup: &'a M,
            link_preview_options: LinkPreviewOptions,
        }
        let body = Body {
            chat_id,
            text,
            parse_mode: PARSE_MODE,
            reply_markup,
            link_preview_options: NO_PREVIEW,
        };
        let resp = self.post("sendMessage", &body).await?;
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
            parse_mode: &'static str,
            link_preview_options: LinkPreviewOptions,
            #[serde(skip_serializing_if = "Option::is_none")]
            reply_markup: Option<ReplyMarkup<'a>>,
        }
        let body = Body {
            chat_id,
            message_id,
            text,
            parse_mode: PARSE_MODE,
            link_preview_options: NO_PREVIEW,
            reply_markup: keyboard.map(|inline_keyboard| ReplyMarkup { inline_keyboard }),
        };
        self.post("editMessageText", &body).await.map(|_| ())
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
        )
        .await
        .map(|_| ())
    }

    /// `setMyCommands`: the command menu shown to clients of `language_code`,
    /// or to every client without a list of its own when `None`. Commands go
    /// without the leading slash.
    pub async fn set_my_commands(
        &self,
        commands: &[(&str, &str)],
        language_code: Option<&str>,
    ) -> AdapterResult<()> {
        #[derive(Serialize)]
        struct BotCommand<'a> {
            command: &'a str,
            description: &'a str,
        }
        #[derive(Serialize)]
        struct Body<'a> {
            commands: Vec<BotCommand<'a>>,
            #[serde(skip_serializing_if = "Option::is_none")]
            language_code: Option<&'a str>,
        }
        let body = Body {
            commands: commands
                .iter()
                .map(|(command, description)| BotCommand {
                    command,
                    description,
                })
                .collect(),
            language_code,
        };
        self.post("setMyCommands", &body).await.map(|_| ())
    }

    /// POST a JSON body to a Bot API method, mapping HTTP status into
    /// the adapter's error taxonomy. Returns the raw success response
    /// so callers that need the result payload can decode it.
    async fn post(&self, method: &str, body: &impl Serialize) -> AdapterResult<reqwest::Response> {
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

        // 403 (bot blocked or kicked, chat deleted) and 400 "chat not found"
        // mean the chat is gone for good. Any other 400 is about the
        // request, not the chat; 401 is a bad token.
        let code = status.as_u16();
        let snippet = response
            .text()
            .await
            .unwrap_or_else(|_| String::from("(body unreadable)"));
        match code {
            401 => Err(AdapterError::Auth(format!("telegram 401: {snippet}"))),
            403 => Err(AdapterError::InvalidRecipient(format!(
                "telegram {code}: {snippet}"
            ))),
            400 if snippet.contains("chat not found") => Err(AdapterError::InvalidRecipient(
                format!("telegram {code}: {snippet}"),
            )),
            _ => Err(AdapterError::Server(format!("telegram {code}: {snippet}"))),
        }
    }
}
