// SPDX-License-Identifier: AGPL-3.0-or-later

//! Stratum V1 JSON-RPC wire layer: [`parse_request`] turns a line into a
//! typed [`SV1Request`] or [`FrameParseError`], the `write_*` functions emit
//! `\n`-terminated frames whose field order is pinned by `Serialize` structs
//! so the JSON is byte-stable. `mining.notify` lives in `notify.rs`.

use std::borrow::Cow;

use serde::de::{self, SeqAccess, Visitor};
use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;

// ── Wire constants — error codes and rejection strings ────────────────

/// SV1 wire-level error codes. Wire-level "stale" reuses [`ERR_JOB_NOT_FOUND`]
/// because SV1 has no separate stale code (the internal stat counter is
/// distinct via [`REJECT_STALE`], but miners only see code 21).
pub(crate) const ERR_OTHER_UNKNOWN: i64 = 20;
pub(crate) const ERR_JOB_NOT_FOUND: i64 = 21;
pub(crate) const ERR_DUPLICATE_SHARE: i64 = 22;
pub(crate) const ERR_LOW_DIFFICULTY_SHARE: i64 = 23;
pub(crate) const ERR_UNAUTHORIZED_WORKER: i64 = 24;
pub(crate) const ERR_NOT_SUBSCRIBED: i64 = 25;

/// Submit-path reject-reason strings. **These bytes are observable** and
/// some monitoring tooling parses them; do not paraphrase.
pub(crate) const REJECT_JOB_NOT_FOUND: &str = "Job not found";
pub(crate) const REJECT_DUPLICATE: &str = "Duplicate share";
pub(crate) const REJECT_LOW_DIFF: &str = "Difficulty too low";
pub(crate) const REJECT_STALE: &str = "stale";
pub(crate) const REJECT_UNAUTHORIZED: &str = "Unauthorized worker";
pub(crate) const REJECT_NOT_SUBSCRIBED: &str = "Not subscribed";
/// Emitted when a miner changes version bits outside the mask it negotiated
/// (BIP-310).
pub(crate) const REJECT_VERSION_ROLLING: &str = "Version rolling not allowed";
pub(crate) const REJECT_SUGGEST_DISABLED: &str =
    "Suggest difficulty is disabled for this connection";
pub(crate) const REJECT_INVALID_ADDR: &str = "Invalid Bitcoin address";

/// Validation-failure messages — emitted when `parse_request` returns
/// [`FrameParseError::Validation`].
pub(crate) const VALIDATION_INVALID_SUBSCRIBE: &str = "Invalid subscription message";
pub(crate) const VALIDATION_INVALID_CONFIGURE: &str = "Invalid configuration message";
pub(crate) const VALIDATION_INVALID_AUTHORIZE: &str = "Invalid authorization message";
pub(crate) const VALIDATION_INVALID_SUGGEST: &str = "Invalid suggest difficulty message";
pub(crate) const VALIDATION_INVALID_SUBMIT: &str = "Invalid mining submit message";

// ── RpcId — preserves the inbound id through to the response ─────────

/// JSON-RPC request id. The SV1 wire allows numbers, strings, and null.
/// `null` is reserved for server-initiated notifications
/// (`mining.notify`, `mining.set_difficulty`).
#[derive(Clone, Debug, PartialEq)]
pub enum RpcId {
    Null,
    Num(serde_json::Number),
    Str(String),
}

impl RpcId {
    fn from_value(v: serde_json::Value) -> Self {
        match v {
            serde_json::Value::Null => RpcId::Null,
            serde_json::Value::Number(n) => RpcId::Num(n),
            serde_json::Value::String(s) => RpcId::Str(s),
            // Objects / arrays in the id field are spec-illegal but some
            // sloppy probers send them; coerce to Null rather than reject
            // the whole frame.
            _ => RpcId::Null,
        }
    }
}

impl From<i64> for RpcId {
    fn from(n: i64) -> Self {
        RpcId::Num(serde_json::Number::from(n))
    }
}

impl From<&str> for RpcId {
    fn from(s: &str) -> Self {
        RpcId::Str(s.to_string())
    }
}

impl Serialize for RpcId {
    fn serialize<S: serde::Serializer>(&self, ser: S) -> Result<S::Ok, S::Error> {
        match self {
            RpcId::Null => ser.serialize_unit(),
            RpcId::Num(n) => n.serialize(ser),
            RpcId::Str(s) => ser.serialize_str(s),
        }
    }
}

impl<'de> Deserialize<'de> for RpcId {
    fn deserialize<D: serde::Deserializer<'de>>(de: D) -> Result<Self, D::Error> {
        Ok(RpcId::from_value(serde_json::Value::deserialize(de)?))
    }
}

// ── Request types — one per SV1 method ───────────────────────────────

#[derive(Clone, Debug, PartialEq)]
pub struct SubscribeRequest {
    pub id: RpcId,
    /// `None` when the client sent `params: []` (Braiins-style probe).
    pub raw_user_agent: Option<String>,
    /// Normalised label for behaviour dispatch and stats; `"unknown"` when
    /// `raw_user_agent` is absent.
    pub user_agent: String,
}

/// What a `mining.configure` carried in `version-rolling.mask`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RequestedMask {
    /// A readable mask.
    Requested(u32),
    /// No `version-rolling.mask` field. BIP-310 reads this as `ffffffff`.
    Absent,
    /// The field was present but unreadable. **Not** the same as absent.
    Malformed,
}

#[derive(Clone, Debug, PartialEq)]
pub struct ConfigureRequest {
    pub id: RpcId,
    /// The `params` array verbatim, so tooling can inspect more than the one
    /// field [`Self::requested_version_rolling_mask`] reads.
    pub params: serde_json::Value,
}

impl ConfigureRequest {
    /// The `version-rolling.mask` the miner asked for. BIP-310 defaults an
    /// absent field to `ffffffff` (everything), but a present-and-unreadable
    /// one is `Malformed` and must never be upgraded to that default, or the
    /// miner gets bits it never asked for.
    pub fn requested_version_rolling_mask(&self) -> RequestedMask {
        let Some(field) = self
            .params
            .get(1)
            .and_then(|p| p.get("version-rolling.mask"))
        else {
            return RequestedMask::Absent;
        };
        let Some(text) = field.as_str() else {
            return RequestedMask::Malformed;
        };
        // Exactly one optional `0x`, case-insensitively; `from_str_radix`
        // would otherwise also accept a leading `+`.
        let digits = text
            .strip_prefix("0x")
            .or_else(|| text.strip_prefix("0X"))
            .unwrap_or(text);
        if digits.is_empty() || !digits.chars().all(|c| c.is_ascii_hexdigit()) {
            return RequestedMask::Malformed;
        }
        match u32::from_str_radix(digits, 16) {
            Ok(mask) => RequestedMask::Requested(mask),
            Err(_) => RequestedMask::Malformed,
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct AuthorizeRequest {
    pub id: RpcId,
    /// The full `address.worker` string the miner sent.
    pub raw_username: String,
    /// Substring before the first `.`. NOT yet normalised — address
    /// trim / bech32-lowercase / validation happens downstream.
    pub address: String,
    /// Substring after the first `.`, or `"worker"` if no dot was found.
    pub worker: String,
    pub password: Option<String>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct SuggestDifficultyRequest {
    pub id: RpcId,
    /// Always `> 0` (validation rejects zero / negative / non-number).
    pub suggested_difficulty: f64,
}

/// `mining.submit`, the per-share hot path: every field borrows from the
/// inbound line, and `worker` only allocates when the JSON carried an escape.
/// That borrow holds only because `worker` goes through `CowStr`, not the
/// blanket `Deserialize for Cow`, which always allocates.
#[derive(Clone, Debug, PartialEq)]
pub struct SubmitRequest<'a> {
    pub id: RpcId,
    /// `params[0]` — `address.worker` echoed by the miner.
    pub worker: Cow<'a, str>,
    /// `params[1]` — hex job id as advertised in `mining.notify`.
    pub job_id: &'a str,
    /// `params[2]` — hex extranonce2.
    pub extranonce2_hex: &'a str,
    /// `params[3]` — hex ntime.
    pub ntime_hex: &'a str,
    /// `params[4]` — hex nonce.
    pub nonce_hex: &'a str,
    /// `params[5]` — hex version-rolling mask. Absent/null falls back to `"0"`.
    pub version_mask_hex: &'a str,
}

/// Typed inbound SV1 request. Only the hot-path [`SubmitRequest`] borrows;
/// the once-per-connection setup variants own their data.
#[derive(Clone, Debug, PartialEq)]
pub enum SV1Request<'a> {
    Subscribe(SubscribeRequest),
    Configure(ConfigureRequest),
    Authorize(AuthorizeRequest),
    SuggestDifficulty(SuggestDifficultyRequest),
    Submit(SubmitRequest<'a>),
    /// `mining.extranonce.subscribe`.
    ExtranonceSubscribe(RpcId),
    /// Any other `method`, kept for diagnostic logging.
    Other {
        id: RpcId,
        method: String,
    },
}

// ── Parse errors ─────────────────────────────────────────────────────

/// Outcome of [`parse_request`] when the line is unusable.
#[derive(Debug, PartialEq)]
pub enum FrameParseError {
    /// The line is not valid JSON. Connection-fatal: no response is emitted.
    InvalidJson,
    /// JSON parsed but failed shape validation (missing id, params not
    /// an array, wrong param types, etc). Caller emits an error frame
    /// with the carried `code` and `message`.
    Validation {
        id: RpcId,
        code: i64,
        message: &'static str,
    },
}

// ── Parser ───────────────────────────────────────────────────────────

/// A `Cow<str>` that actually borrows from the input. serde's blanket
/// `Deserialize for Cow` always yields `Cow::Owned`, and `#[serde(borrow)]`
/// does not reach through `Option`, so this visitor borrows directly and
/// only allocates when serde had to unescape.
struct CowStr<'a>(Cow<'a, str>);

impl<'de> Deserialize<'de> for CowStr<'de> {
    fn deserialize<D: serde::Deserializer<'de>>(de: D) -> Result<Self, D::Error> {
        struct CowStrVisitor;
        impl<'de> Visitor<'de> for CowStrVisitor {
            type Value = CowStr<'de>;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("a string")
            }
            /// No escapes: the value is a contiguous span of the input.
            fn visit_borrowed_str<E: de::Error>(self, v: &'de str) -> Result<Self::Value, E> {
                Ok(CowStr(Cow::Borrowed(v)))
            }
            /// Unescaped into serde's scratch buffer — must be copied out.
            fn visit_str<E: de::Error>(self, v: &str) -> Result<Self::Value, E> {
                Ok(CowStr(Cow::Owned(v.to_string())))
            }
            fn visit_string<E: de::Error>(self, v: String) -> Result<Self::Value, E> {
                Ok(CowStr(Cow::Owned(v)))
            }
        }
        de.deserialize_str(CowStrVisitor)
    }
}

/// `Option<Cow<str>>` field adapter over [`CowStr`] — keeps the borrow.
fn deserialize_opt_cow_str<'de, D>(de: D) -> Result<Option<Cow<'de, str>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Ok(Option::<CowStr<'de>>::deserialize(de)?.map(|c| c.0))
}

/// Zero-copy view of the JSON-RPC envelope. `serde_json::from_str` fills
/// this without building a DOM: `method` borrows the input string and
/// `id` / `params` are captured as un-parsed [`RawValue`] spans. Unknown
/// fields are ignored; missing fields default to `None`.
#[derive(Deserialize)]
struct Envelope<'a> {
    #[serde(default, borrow)]
    id: Option<&'a RawValue>,
    #[serde(default, borrow, deserialize_with = "deserialize_opt_cow_str")]
    method: Option<Cow<'a, str>>,
    #[serde(default, borrow)]
    params: Option<&'a RawValue>,
}

/// Borrowed view of a `mining.submit` `params` array, read without a DOM.
/// The five required params must be strings; a missing / null / non-string
/// sixth (version mask) falls back to `"0"` at the call site.
struct SubmitParams<'a> {
    worker: Cow<'a, str>,
    job_id: &'a str,
    extranonce2: &'a str,
    ntime: &'a str,
    nonce: &'a str,
    /// `Some(hex)` only if `params[5]` is a JSON string; otherwise `None`.
    version_mask: Option<&'a str>,
}

impl<'de> Deserialize<'de> for SubmitParams<'de> {
    fn deserialize<D: serde::Deserializer<'de>>(de: D) -> Result<Self, D::Error> {
        struct SeqVisitor;
        impl<'de> Visitor<'de> for SeqVisitor {
            type Value = SubmitParams<'de>;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("a mining.submit params array of five hex strings")
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
                // `CowStr` (not a bare `Cow`) so a plain worker name is
                // borrowed from the input instead of allocated — see its docs.
                let worker: CowStr<'de> = seq
                    .next_element()?
                    .ok_or_else(|| de::Error::invalid_length(0, &self))?;
                let worker = worker.0;
                let job_id: &str = seq
                    .next_element()?
                    .ok_or_else(|| de::Error::invalid_length(1, &self))?;
                let extranonce2: &str = seq
                    .next_element()?
                    .ok_or_else(|| de::Error::invalid_length(2, &self))?;
                let ntime: &str = seq
                    .next_element()?
                    .ok_or_else(|| de::Error::invalid_length(3, &self))?;
                let nonce: &str = seq
                    .next_element()?
                    .ok_or_else(|| de::Error::invalid_length(4, &self))?;
                // Sixth param is optional. Read it as a raw span so a null /
                // numeric / bool value degrades to "no mask" rather than
                // failing the whole submit.
                let version_mask = match seq.next_element::<&RawValue>()? {
                    Some(raw) if raw.get().starts_with('"') => {
                        serde_json::from_str::<&str>(raw.get()).ok()
                    }
                    _ => None,
                };
                // Drain any surplus params so trailing junk doesn't error.
                while seq.next_element::<de::IgnoredAny>()?.is_some() {}
                Ok(SubmitParams {
                    worker,
                    job_id,
                    extranonce2,
                    ntime,
                    nonce,
                    version_mask,
                })
            }
        }
        de.deserialize_seq(SeqVisitor)
    }
}

/// Parse one JSON-RPC line (without its newline) into a typed `SV1Request`.
/// Surrounding whitespace is trimmed because the protocol router only peeks,
/// so a connection that leads with a space/CR/LF arrives here intact.
pub fn parse_request(line: &str) -> Result<SV1Request<'_>, FrameParseError> {
    let trimmed = line.trim();
    // Envelope only, no DOM: submit reads its params from the borrowed span,
    // the cold setup methods build a small DOM below.
    let envelope: Envelope = match serde_json::from_str(trimmed) {
        Ok(env) => env,
        Err(_) => {
            // Not JSON at all is connection-fatal; valid JSON that is not a
            // request object is tolerated as `Other`.
            return match serde_json::from_str::<&RawValue>(trimmed) {
                Ok(_) => Ok(SV1Request::Other {
                    id: RpcId::Null,
                    method: String::new(),
                }),
                Err(_) => Err(FrameParseError::InvalidJson),
            };
        }
    };

    // Resolve the id once. `id_present` is "present and not literal null":
    // an object/array id is spec-illegal but counts as present (and then
    // coerces to `Null`).
    let (id, id_present) = match envelope.id {
        Some(raw) => {
            let token = raw.get().trim();
            let present = token != "null";
            let id = serde_json::from_str::<RpcId>(token).unwrap_or(RpcId::Null);
            (id, present)
        }
        None => (RpcId::Null, false),
    };

    let method = envelope.method.as_deref().unwrap_or("");

    // ── Hot path: mining.submit — borrowed, no DOM ───────────────────
    if method == "mining.submit" {
        if !id_present {
            return Err(FrameParseError::Validation {
                id,
                code: ERR_OTHER_UNKNOWN,
                message: VALIDATION_INVALID_SUBMIT,
            });
        }
        // A non-array, short array or non-string in the first five
        // positions fails deserialisation and becomes an invalid submit.
        let parsed = envelope
            .params
            .and_then(|raw| serde_json::from_str::<SubmitParams<'_>>(raw.get()).ok());
        return match parsed {
            Some(p) => Ok(SV1Request::Submit(SubmitRequest {
                id,
                worker: p.worker,
                job_id: p.job_id,
                extranonce2_hex: p.extranonce2,
                ntime_hex: p.ntime,
                nonce_hex: p.nonce,
                version_mask_hex: p.version_mask.unwrap_or("0"),
            })),
            None => Err(FrameParseError::Validation {
                id,
                code: ERR_OTHER_UNKNOWN,
                message: VALIDATION_INVALID_SUBMIT,
            }),
        };
    }

    // ── Cold paths: session-setup methods ────────────────────────────
    // Once per connection, so a small DOM here costs nothing in steady state.
    let params_dom: Option<serde_json::Value> = envelope
        .params
        .and_then(|raw| serde_json::from_str(raw.get()).ok());
    let params = params_dom.as_ref();

    match method {
        "mining.subscribe" => {
            if !id_present || !params.is_some_and(|p| p.is_array()) {
                return Err(FrameParseError::Validation {
                    id,
                    code: ERR_OTHER_UNKNOWN,
                    message: VALIDATION_INVALID_SUBSCRIBE,
                });
            }
            // params[0] is optional: marketplace probers send `params: []`.
            let arr = params.unwrap().as_array().unwrap();
            let raw_ua = arr.first().and_then(|v| v.as_str()).map(String::from);
            let user_agent = raw_ua
                .as_deref()
                .map(bp_common::normalize_user_agent)
                .unwrap_or_else(|| "unknown".to_string());
            Ok(SV1Request::Subscribe(SubscribeRequest {
                id,
                raw_user_agent: raw_ua,
                user_agent,
            }))
        }
        "mining.configure" => {
            if !id_present || !params.is_some_and(|p| p.is_array()) {
                return Err(FrameParseError::Validation {
                    id,
                    code: ERR_OTHER_UNKNOWN,
                    message: VALIDATION_INVALID_CONFIGURE,
                });
            }
            let params_value = params.cloned().unwrap_or(serde_json::Value::Array(vec![]));
            Ok(SV1Request::Configure(ConfigureRequest {
                id,
                params: params_value,
            }))
        }
        "mining.authorize" => {
            if !id_present || !params.is_some_and(|p| p.is_array()) {
                return Err(FrameParseError::Validation {
                    id,
                    code: ERR_OTHER_UNKNOWN,
                    message: VALIDATION_INVALID_AUTHORIZE,
                });
            }
            let arr = params.unwrap().as_array().unwrap();
            if arr.len() < 2 || !arr[0].is_string() {
                return Err(FrameParseError::Validation {
                    id,
                    code: ERR_OTHER_UNKNOWN,
                    message: VALIDATION_INVALID_AUTHORIZE,
                });
            }
            let raw_username = arr[0].as_str().unwrap().to_string();
            // "addr." gets the no-dot default: the share path writes under a
            // non-empty name, so a "" client row would go stale and
            // `kill_dead_clients` would sweep a live session.
            let (address, worker) = match bp_common::split_user_identity(&raw_username) {
                (a, Some(w)) if !w.is_empty() => (a.to_string(), w.to_string()),
                (a, _) => (a.to_string(), "worker".to_string()),
            };
            let password = arr.get(1).and_then(|v| v.as_str()).map(String::from);
            Ok(SV1Request::Authorize(AuthorizeRequest {
                id,
                raw_username,
                address,
                worker,
                password,
            }))
        }
        "mining.suggest_difficulty" => {
            if !id_present {
                return Err(FrameParseError::Validation {
                    id,
                    code: ERR_OTHER_UNKNOWN,
                    message: VALIDATION_INVALID_SUGGEST,
                });
            }
            let arr = params.and_then(|p| p.as_array());
            let diff = arr
                .and_then(|a| a.first())
                .and_then(|v| v.as_f64())
                .filter(|n| *n > 0.0);
            match diff {
                Some(d) => Ok(SV1Request::SuggestDifficulty(SuggestDifficultyRequest {
                    id,
                    suggested_difficulty: d,
                })),
                None => Err(FrameParseError::Validation {
                    id,
                    code: ERR_OTHER_UNKNOWN,
                    message: VALIDATION_INVALID_SUGGEST,
                }),
            }
        }
        "mining.extranonce.subscribe" => Ok(SV1Request::ExtranonceSubscribe(id)),
        other => Ok(SV1Request::Other {
            id,
            method: other.to_string(),
        }),
    }
}

// ── Writers — byte-pinned via Serialize-derived structs ──────────────

#[derive(Serialize)]
struct SuccessFrame<'a, R: Serialize> {
    id: &'a RpcId,
    error: (),
    result: R,
}

#[derive(Serialize)]
struct ErrorFrame<'a> {
    id: &'a RpcId,
    result: (),
    error: (i64, &'a str, &'static str),
}

#[derive(Serialize)]
struct NotificationFrame<'a, P: Serialize> {
    id: (),
    method: &'a str,
    params: P,
}

#[derive(Serialize)]
struct ConfigureResult<'a> {
    #[serde(rename = "version-rolling")]
    version_rolling: bool,
    #[serde(rename = "version-rolling.mask")]
    version_rolling_mask: &'a str,
}

/// Emit a `mining.subscribe` response.
///
/// Wire shape:
/// `{"id":<id>,"error":null,"result":[[["mining.notify","<sid>"]],"<en1>",<en2_size>]}`
pub(crate) fn write_subscribe_response(
    id: &RpcId,
    session_id: &str,
    extranonce1_hex: &str,
    extranonce2_size: u8,
) -> Vec<u8> {
    let result = (
        vec![("mining.notify", session_id)],
        extranonce1_hex,
        extranonce2_size,
    );
    let frame = SuccessFrame {
        id,
        error: (),
        result,
    };
    finalize(&frame)
}

/// Emit a `mining.configure` response: always `version-rolling: true` with
/// the mask as 8-digit lowercase hex, whatever extensions were requested.
pub(crate) fn write_configure_response(id: &RpcId, version_rolling_mask: u32) -> Vec<u8> {
    let mask = format!("{:08x}", version_rolling_mask);
    let frame = SuccessFrame {
        id,
        error: (),
        result: ConfigureResult {
            version_rolling: true,
            version_rolling_mask: &mask,
        },
    };
    finalize(&frame)
}

/// Emit a `mining.authorize` response: `{"id":<id>,"error":null,"result":true}`.
pub(crate) fn write_authorize_response(id: &RpcId) -> Vec<u8> {
    let frame = SuccessFrame {
        id,
        error: (),
        result: true,
    };
    finalize(&frame)
}

/// Emit a `mining.submit` success response.
pub(crate) fn write_submit_success(id: &RpcId) -> Vec<u8> {
    let frame = SuccessFrame {
        id,
        error: (),
        result: true,
    };
    finalize(&frame)
}

/// Emit a server-initiated `mining.set_difficulty` notification (no id).
///
/// An integer-valued `difficulty` emits as a bare integer (`[1024]`), a
/// fractional one as a float (`[0.1]`).
pub(crate) fn write_set_difficulty(difficulty: f64) -> Vec<u8> {
    let frame = NotificationFrame {
        id: (),
        method: "mining.set_difficulty",
        params: [difficulty_to_json_number(difficulty)],
    };
    finalize(&frame)
}

/// Emit a `mining.extranonce.subscribe` response. It only confirms: the pool
/// never follows up with `mining.set_extranonce`.
pub(crate) fn write_extranonce_subscribe_response(id: &RpcId) -> Vec<u8> {
    let frame = SuccessFrame {
        id,
        error: (),
        result: true,
    };
    finalize(&frame)
}

/// Emit `{"id":<id>,"result":null,"error":[<code>,"<msg>",""]}`; the third
/// element stays empty because no validation details are collected.
pub(crate) fn write_error(id: &RpcId, code: i64, message: &str) -> Vec<u8> {
    let frame = ErrorFrame {
        id,
        result: (),
        error: (code, message, ""),
    };
    finalize(&frame)
}

fn finalize<F: Serialize>(frame: &F) -> Vec<u8> {
    let mut bytes =
        serde_json::to_vec(frame).expect("response/notification shapes are always valid JSON");
    bytes.push(b'\n');
    bytes
}

/// Integer-valued finite `f64` → JSON integer; otherwise → JSON float.
fn difficulty_to_json_number(d: f64) -> serde_json::Number {
    if d.is_finite() && d.fract() == 0.0 && d.abs() <= (i64::MAX as f64) {
        serde_json::Number::from(d as i64)
    } else {
        // `from_f64` returns `None` only for NaN / ±Infinity, which vardiff
        // validation keeps out; firing here means a bug upstream.
        serde_json::Number::from_f64(d).expect("difficulty must be finite for wire emission")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // ─ Parser: subscribe ─────────────────────────────────────────────

    #[test]
    fn parse_subscribe_with_user_agent() {
        let req =
            parse_request(r#"{"id":1,"method":"mining.subscribe","params":["cgminer/4.11.1"]}"#)
                .expect("ok");
        match req {
            SV1Request::Subscribe(s) => {
                assert_eq!(s.id, RpcId::from(1));
                assert_eq!(s.raw_user_agent.as_deref(), Some("cgminer/4.11.1"));
                assert_eq!(s.user_agent, "cgminer");
            }
            other => panic!("expected Subscribe, got {:?}", other),
        }
    }

    #[test]
    fn parse_subscribe_with_empty_params() {
        let req = parse_request(r#"{"id":1,"method":"mining.subscribe","params":[]}"#).expect("ok");
        match req {
            SV1Request::Subscribe(s) => {
                assert!(s.raw_user_agent.is_none());
                assert_eq!(s.user_agent, "unknown");
            }
            other => panic!("expected Subscribe, got {:?}", other),
        }
    }

    #[test]
    fn parse_subscribe_rejects_missing_params() {
        let res = parse_request(r#"{"id":1,"method":"mining.subscribe"}"#);
        assert_eq!(
            res,
            Err(FrameParseError::Validation {
                id: RpcId::from(1),
                code: ERR_OTHER_UNKNOWN,
                message: VALIDATION_INVALID_SUBSCRIBE,
            })
        );
    }

    #[test]
    fn parse_subscribe_rejects_null_id() {
        let res = parse_request(r#"{"id":null,"method":"mining.subscribe","params":[]}"#);
        assert!(matches!(
            res,
            Err(FrameParseError::Validation {
                message: VALIDATION_INVALID_SUBSCRIBE,
                ..
            })
        ));
    }

    #[test]
    fn parse_subscribe_rejects_params_object() {
        let res = parse_request(r#"{"id":1,"method":"mining.subscribe","params":{}}"#);
        assert!(matches!(
            res,
            Err(FrameParseError::Validation {
                message: VALIDATION_INVALID_SUBSCRIBE,
                ..
            })
        ));
    }

    // ─ Parser: configure ─────────────────────────────────────────────

    #[test]
    fn parse_configure_keeps_raw_params() {
        let req = parse_request(
            r#"{"id":2,"method":"mining.configure","params":[["version-rolling"],{"version-rolling.mask":"ffffffff"}]}"#,
        )
        .expect("ok");
        match req {
            SV1Request::Configure(c) => {
                assert_eq!(c.id, RpcId::from(2));
                assert!(c.params.is_array());
                assert_eq!(c.params.as_array().unwrap().len(), 2);
            }
            other => panic!("expected Configure, got {:?}", other),
        }
    }

    #[test]
    fn parse_configure_rejects_non_array_params() {
        let res = parse_request(r#"{"id":1,"method":"mining.configure","params":42}"#);
        assert!(matches!(
            res,
            Err(FrameParseError::Validation {
                message: VALIDATION_INVALID_CONFIGURE,
                ..
            })
        ));
    }

    // ─ Parser: authorize ─────────────────────────────────────────────

    #[test]
    fn parse_authorize_splits_address_dot_worker() {
        let req = parse_request(
            r#"{"id":3,"method":"mining.authorize","params":["bc1qaddress.worker1","x"]}"#,
        )
        .expect("ok");
        match req {
            SV1Request::Authorize(a) => {
                assert_eq!(a.raw_username, "bc1qaddress.worker1");
                assert_eq!(a.address, "bc1qaddress");
                assert_eq!(a.worker, "worker1");
                assert_eq!(a.password.as_deref(), Some("x"));
            }
            other => panic!("expected Authorize, got {:?}", other),
        }
    }

    #[test]
    fn parse_authorize_defaults_worker_to_literal_when_no_dot() {
        let req = parse_request(
            r#"{"id":3,"method":"mining.authorize","params":["bc1qjustaddress",""]}"#,
        )
        .expect("ok");
        match req {
            SV1Request::Authorize(a) => {
                assert_eq!(a.address, "bc1qjustaddress");
                assert_eq!(a.worker, "worker"); // defaults to 'worker' if missing
            }
            _ => unreachable!(),
        }
    }

    /// A trailing dot must never yield an empty worker name.
    #[test]
    fn parse_authorize_with_trailing_dot_gets_the_default_worker_name() {
        let req = parse_request(
            r#"{"id":3,"method":"mining.authorize","params":["bc1qjustaddress.","x"]}"#,
        )
        .expect("ok");
        match req {
            SV1Request::Authorize(a) => {
                assert_eq!(a.address, "bc1qjustaddress");
                assert_eq!(a.worker, "worker", "empty worker takes the no-dot default");
            }
            _ => unreachable!(),
        }
    }

    #[test]
    fn parse_authorize_rejects_when_params_too_short() {
        let res = parse_request(r#"{"id":3,"method":"mining.authorize","params":["only-one"]}"#);
        assert!(matches!(
            res,
            Err(FrameParseError::Validation {
                message: VALIDATION_INVALID_AUTHORIZE,
                ..
            })
        ));
    }

    #[test]
    fn parse_authorize_rejects_when_first_param_not_string() {
        let res = parse_request(r#"{"id":3,"method":"mining.authorize","params":[42,"x"]}"#);
        assert!(matches!(
            res,
            Err(FrameParseError::Validation {
                message: VALIDATION_INVALID_AUTHORIZE,
                ..
            })
        ));
    }

    // ─ Parser: suggest_difficulty ────────────────────────────────────

    #[test]
    fn parse_suggest_difficulty_accepts_positive_number() {
        let req =
            parse_request(r#"{"id":4,"method":"mining.suggest_difficulty","params":[16384]}"#)
                .expect("ok");
        match req {
            SV1Request::SuggestDifficulty(s) => {
                assert_eq!(s.suggested_difficulty, 16384.0);
            }
            _ => unreachable!(),
        }
    }

    #[test]
    fn parse_suggest_difficulty_rejects_zero() {
        let res = parse_request(r#"{"id":4,"method":"mining.suggest_difficulty","params":[0]}"#);
        assert!(matches!(
            res,
            Err(FrameParseError::Validation {
                message: VALIDATION_INVALID_SUGGEST,
                ..
            })
        ));
    }

    #[test]
    fn parse_suggest_difficulty_rejects_negative() {
        let res = parse_request(r#"{"id":4,"method":"mining.suggest_difficulty","params":[-1]}"#);
        assert!(matches!(
            res,
            Err(FrameParseError::Validation {
                message: VALIDATION_INVALID_SUGGEST,
                ..
            })
        ));
    }

    #[test]
    fn parse_suggest_difficulty_rejects_string_value() {
        let res =
            parse_request(r#"{"id":4,"method":"mining.suggest_difficulty","params":["1024"]}"#);
        assert!(matches!(
            res,
            Err(FrameParseError::Validation {
                message: VALIDATION_INVALID_SUGGEST,
                ..
            })
        ));
    }

    // ─ Parser: submit ────────────────────────────────────────────────

    #[test]
    fn parse_submit_with_version_mask() {
        let req = parse_request(
            r#"{"id":5,"method":"mining.submit","params":["addr.w","000a","11223344556677","65a1b2c3","deadbeef","1fffe000"]}"#,
        )
        .expect("ok");
        match req {
            SV1Request::Submit(s) => {
                assert_eq!(&*s.worker, "addr.w");
                assert_eq!(s.job_id, "000a");
                assert_eq!(s.extranonce2_hex, "11223344556677");
                assert_eq!(s.ntime_hex, "65a1b2c3");
                assert_eq!(s.nonce_hex, "deadbeef");
                assert_eq!(s.version_mask_hex, "1fffe000");
            }
            _ => unreachable!(),
        }
    }

    #[test]
    fn parse_submit_defaults_version_mask_to_zero_when_absent() {
        let req = parse_request(
            r#"{"id":5,"method":"mining.submit","params":["addr.w","000a","1122","ntime","nonce"]}"#,
        )
        .expect("ok");
        match req {
            SV1Request::Submit(s) => assert_eq!(s.version_mask_hex, "0"),
            _ => unreachable!(),
        }
    }

    #[test]
    fn parse_submit_defaults_version_mask_to_zero_when_null() {
        let req = parse_request(
            r#"{"id":5,"method":"mining.submit","params":["addr.w","000a","1122","ntime","nonce",null]}"#,
        )
        .expect("ok");
        match req {
            SV1Request::Submit(s) => assert_eq!(s.version_mask_hex, "0"),
            _ => unreachable!(),
        }
    }

    #[test]
    fn parse_submit_rejects_short_params() {
        let res = parse_request(
            r#"{"id":5,"method":"mining.submit","params":["addr.w","000a","1122","ntime"]}"#,
        );
        assert!(matches!(
            res,
            Err(FrameParseError::Validation {
                message: VALIDATION_INVALID_SUBMIT,
                ..
            })
        ));
    }

    #[test]
    fn parse_submit_numeric_sixth_param_defaults_mask_to_zero() {
        // A non-string version mask (number / bool) is tolerated as "absent"
        // → "0", rather than failing the whole submit.
        let req = parse_request(
            r#"{"id":5,"method":"mining.submit","params":["addr.w","000a","1122","ntime","nonce",123]}"#,
        )
        .expect("ok");
        match req {
            SV1Request::Submit(s) => assert_eq!(s.version_mask_hex, "0"),
            _ => unreachable!(),
        }
    }

    #[test]
    fn parse_submit_drains_surplus_params() {
        // Extra trailing params beyond the optional sixth must not error.
        let req = parse_request(
            r#"{"id":5,"method":"mining.submit","params":["addr.w","000a","1122","ntime","nonce","1fffe000","junk",42]}"#,
        )
        .expect("ok");
        match req {
            SV1Request::Submit(s) => assert_eq!(s.version_mask_hex, "1fffe000"),
            _ => unreachable!(),
        }
    }

    /// A plain worker name is borrowed from the input, so submit does not
    /// allocate per share.
    #[test]
    fn parse_submit_plain_worker_is_borrowed_not_allocated() {
        let line = r#"{"id":5,"method":"mining.submit","params":["bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4.worker1","000a","1122","ntime","nonce"]}"#;
        let req = parse_request(line).expect("ok");
        match req {
            SV1Request::Submit(s) => {
                assert_eq!(
                    &*s.worker,
                    "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4.worker1"
                );
                assert!(
                    matches!(s.worker, std::borrow::Cow::Borrowed(_)),
                    "a plain worker name must borrow from the input, not allocate"
                );
            }
            _ => unreachable!(),
        }
    }

    /// Same contract for the envelope's `method`: `#[serde(borrow)]` alone
    /// does not reach through `Option<Cow<_>>`.
    #[test]
    fn envelope_plain_method_is_borrowed_not_allocated() {
        let line = r#"{"id":1,"method":"mining.submit","params":[]}"#;
        let env: Envelope = serde_json::from_str(line).expect("envelope");
        let method = env.method.expect("method present");
        assert_eq!(&*method, "mining.submit");
        assert!(
            matches!(method, std::borrow::Cow::Borrowed(_)),
            "a plain method name must borrow from the input, not allocate"
        );
    }

    /// An escaped method still round-trips correctly (unescaping forces an
    /// allocation — the one case where `Cow` must own).
    #[test]
    fn envelope_escaped_method_unescapes_into_owned() {
        // JSON `"a\\b"` is the 3-char value `a\b`; unescaping forces the copy.
        let line = r#"{"id":1,"method":"a\\b","params":[]}"#;
        let env: Envelope = serde_json::from_str(line).expect("envelope");
        let method = env.method.expect("method present");
        assert_eq!(&*method, "a\\b");
        assert!(matches!(method, std::borrow::Cow::Owned(_)));
    }

    #[test]
    fn parse_submit_worker_with_json_escape_unescapes_into_owned() {
        // A worker name carrying a JSON escape can't be borrowed in place;
        // the `Cow` allocates and yields the unescaped value.
        let req = parse_request(
            r#"{"id":5,"method":"mining.submit","params":["a\\b.w","000a","1122","ntime","nonce"]}"#,
        )
        .expect("ok");
        match req {
            SV1Request::Submit(s) => {
                assert_eq!(&*s.worker, "a\\b.w");
                assert!(matches!(s.worker, std::borrow::Cow::Owned(_)));
            }
            _ => unreachable!(),
        }
    }

    #[test]
    fn parse_valid_json_non_object_goes_to_other() {
        // A top-level array is valid JSON but not a request envelope — the
        // lenient catch-all keeps the connection alive (no InvalidJson).
        let req = parse_request("[1,2,3]").expect("ok");
        assert!(matches!(req, SV1Request::Other { .. }));
    }

    #[test]
    fn parse_submit_rejects_non_string_jobid() {
        let res = parse_request(
            r#"{"id":5,"method":"mining.submit","params":["addr.w",42,"1122","ntime","nonce"]}"#,
        );
        assert!(matches!(
            res,
            Err(FrameParseError::Validation {
                message: VALIDATION_INVALID_SUBMIT,
                ..
            })
        ));
    }

    // ─ Parser: misc ──────────────────────────────────────────────────

    #[test]
    fn parse_extranonce_subscribe_keeps_id() {
        let req = parse_request(r#"{"id":99,"method":"mining.extranonce.subscribe","params":[]}"#)
            .expect("ok");
        match req {
            SV1Request::ExtranonceSubscribe(id) => assert_eq!(id, RpcId::from(99)),
            _ => unreachable!(),
        }
    }

    #[test]
    fn parse_unknown_method_goes_to_other() {
        let req =
            parse_request(r#"{"id":7,"method":"mining.fancy_new_thing","params":[]}"#).expect("ok");
        match req {
            SV1Request::Other { id, method } => {
                assert_eq!(id, RpcId::from(7));
                assert_eq!(method, "mining.fancy_new_thing");
            }
            _ => unreachable!(),
        }
    }

    #[test]
    fn parse_invalid_json_is_connection_fatal() {
        // Caller closes the socket.
        let res = parse_request("not a json frame");
        assert_eq!(res, Err(FrameParseError::InvalidJson));
    }

    #[test]
    fn parse_tolerates_leading_whitespace_inside_line() {
        // The protocol router only peeks, so leading whitespace reaches here.
        let req = parse_request("   {\"id\":1,\"method\":\"mining.subscribe\",\"params\":[]}")
            .expect("ok");
        assert!(matches!(req, SV1Request::Subscribe(_)));
    }

    // ─ Writers: byte-pinned outputs ──────────────────────────────────

    fn s(v: &[u8]) -> &str {
        std::str::from_utf8(v).unwrap()
    }

    #[test]
    fn write_subscribe_response_byte_exact() {
        let bytes = write_subscribe_response(&RpcId::from(1), "abcd1234", "abcd1234", 8);
        assert_eq!(
            s(&bytes),
            r#"{"id":1,"error":null,"result":[[["mining.notify","abcd1234"]],"abcd1234",8]}"#
                .to_string()
                + "\n"
        );
    }

    #[test]
    fn write_configure_response_byte_exact() {
        let bytes = write_configure_response(&RpcId::from(2), 0x1fffe000);
        // Lowercase, 8-padded hex.
        assert_eq!(
            s(&bytes),
            r#"{"id":2,"error":null,"result":{"version-rolling":true,"version-rolling.mask":"1fffe000"}}"#
                .to_string()
                + "\n"
        );
    }

    #[test]
    fn write_configure_response_pads_short_mask() {
        // A short numeric mask (e.g. 0x00000001) must still emit 8 hex chars.
        let bytes = write_configure_response(&RpcId::from(2), 1);
        assert_eq!(
            s(&bytes),
            r#"{"id":2,"error":null,"result":{"version-rolling":true,"version-rolling.mask":"00000001"}}"#
                .to_string()
                + "\n"
        );
    }

    #[test]
    fn write_authorize_response_byte_exact() {
        let bytes = write_authorize_response(&RpcId::from(3));
        assert_eq!(s(&bytes), "{\"id\":3,\"error\":null,\"result\":true}\n");
    }

    #[test]
    fn write_submit_success_byte_exact() {
        let bytes = write_submit_success(&RpcId::from(5));
        assert_eq!(s(&bytes), "{\"id\":5,\"error\":null,\"result\":true}\n");
    }

    #[test]
    fn write_set_difficulty_emits_integer_for_integer_valued_diff() {
        // Integer-valued floats serialize as integers: 1024 → "1024".
        let bytes = write_set_difficulty(1024.0);
        assert_eq!(
            s(&bytes),
            "{\"id\":null,\"method\":\"mining.set_difficulty\",\"params\":[1024]}\n"
        );
    }

    #[test]
    fn write_set_difficulty_emits_float_for_fractional_diff() {
        // cpuminer fallback: 0.1 → "0.1".
        let bytes = write_set_difficulty(0.1);
        assert_eq!(
            s(&bytes),
            "{\"id\":null,\"method\":\"mining.set_difficulty\",\"params\":[0.1]}\n"
        );
    }

    #[test]
    fn write_extranonce_subscribe_response_byte_exact() {
        let bytes = write_extranonce_subscribe_response(&RpcId::from(7));
        assert_eq!(s(&bytes), "{\"id\":7,\"error\":null,\"result\":true}\n");
    }

    #[test]
    fn write_error_byte_exact_with_empty_validation_detail() {
        // The third element (validation detail) is always empty.
        let bytes = write_error(
            &RpcId::from(1),
            ERR_OTHER_UNKNOWN,
            "Invalid subscription message",
        );
        assert_eq!(
            s(&bytes),
            "{\"id\":1,\"result\":null,\"error\":[20,\"Invalid subscription message\",\"\"]}\n"
        );
    }

    #[test]
    fn write_error_preserves_string_id() {
        let bytes = write_error(&RpcId::from("xyz"), ERR_JOB_NOT_FOUND, REJECT_JOB_NOT_FOUND);
        assert_eq!(
            s(&bytes),
            "{\"id\":\"xyz\",\"result\":null,\"error\":[21,\"Job not found\",\"\"]}\n"
        );
    }

    #[test]
    fn write_error_preserves_null_id() {
        let bytes = write_error(
            &RpcId::Null,
            ERR_OTHER_UNKNOWN,
            "Invalid subscription message",
        );
        assert_eq!(
            s(&bytes),
            "{\"id\":null,\"result\":null,\"error\":[20,\"Invalid subscription message\",\"\"]}\n"
        );
    }

    // ─ RpcId roundtrips ──────────────────────────────────────────────

    #[test]
    fn rpc_id_serde_roundtrip_num_string_null() {
        for v in [json!(42), json!("abc"), json!(null)] {
            let id: RpcId = serde_json::from_value(v.clone()).unwrap();
            let back = serde_json::to_value(&id).unwrap();
            assert_eq!(back, v);
        }
    }

    #[test]
    fn rpc_id_serde_coerces_object_to_null() {
        // Spec-illegal, but sloppy probers send it.
        let id: RpcId = serde_json::from_value(json!({"foo": 1})).unwrap();
        assert_eq!(id, RpcId::Null);
    }
}
