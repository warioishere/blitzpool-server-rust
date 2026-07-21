# Custom Extranonce API

Let a **Solo** miner pin its own 4-byte extranonce prefix per worker instead of
the pool-allocated one. Authorisation is a **bearer token**: you prove control
of the address **once** by signing a challenge, the API hands you a token, and
every subsequent "set the prefix for worker X" call carries that token. This is
a niche, opt-in feature — most miners never touch it.

---

## How it works (roughly)

Two processes are involved and they do **not** share memory:

1. **API process** — receives your HTTP calls, issues/verifies the token, and
   writes the override into Postgres (`pplns_custom_extranonce`).
2. **Stratum core** — the process your miner actually connects to. It refreshes
   an in-memory copy of the override table from Postgres **every 10 seconds**.
   When your miner opens a channel (and, for an already-armed connection, on
   each new job), the core swaps in your prefix and tells the miner with an SV2
   `SetExtranoncePrefix` message.

So a change you make via the API lands on the core within ~10 s and then applies
at the next opportunity (see [When the EN is used](#when-the-en-is-used)).

There is **no** requirement that the address has ever mined. The token is issued
purely on a valid signature over the challenge — a brand-new, never-mined
address can be verified and have an override set. The prefix takes effect the
first time a miner authorises with that address and opens an Extended channel.

### The auth model

- The **signature** is used exactly once, to issue a token. It is nonced and
  expiring, so it can't be replayed.
- The **token** is the reusable credential. It is a random 32-byte value; only
  its SHA-256 hash is stored server-side (the same pattern as the group admin
  token), so it can't be recovered later — **store it when it's returned**.
- Re-issuing a token (sign a fresh challenge again) **overwrites and revokes**
  the previous one. That is also how you rotate or revoke a leaked token.
- The token's only power is setting a custom extranonce prefix on this address's
  own Solo workers. It can **not** move money — the coinbase still pays the
  address — which is why a long-lived token is an acceptable, low-stakes
  credential.

---

## Endpoints

`challenge` and `token` are rate-limited to **5 requests/minute per client IP**;
`set` to **30/minute** — ample, since one request configures your whole fleet.

### 1. `POST /api/address/extranonce/challenge`

Ask for the exact message to sign. Takes the address only.

```jsonc
// request
{
  "address": "bc1q…"          // your Solo payout address (mainnet)
}
```

```jsonc
// 200 response
{
  "message": "Blitzpool extranonce token request\nAddress: bc1q…\nNonce: …\nIssued(ms): …\nExpires(ms): …",
  "expiresAt": 1730000000000  // epoch ms; the message is valid for 15 minutes
}
```

Sign the returned `message` **verbatim** with the address's private key. Both
signature families are accepted, so any wallet works:

- **BIP-322** (covers taproot `bc1p…` and segwit)
- **BIP-137 / Electrum** legacy recoverable signatures (base64)

The message binds the address, a nonce and an expiry, so a captured signature
can't be replayed after it expires or after the token is issued (the challenge
is consumed on issue).

### 2. `POST /api/address/extranonce/token`

Submit the signature to be issued a token.

```jsonc
// request
{
  "address": "bc1q…",
  "signature": "…"            // base64 (BIP-137) or BIP-322 encoded
}
```

```jsonc
// 200 response
{
  "address": "bc1q…",
  "token": "3f9a…64hex…",      // ← store this; it is shown only once
  "createdAt": 1730000000000
}
```

The signature is verified against the **stored** challenge message (never a
client-supplied one), the challenge is consumed, and a fresh token is returned.
Only the token's hash is kept, so it cannot be retrieved again — if you lose it,
sign a new challenge to mint a replacement (which revokes the old one).

### 3. `POST /api/address/extranonce/set`

Headless, no-UI call: set (or change) the prefix for **one or more** workers
in a single all-or-nothing request. Repeat any time with the **same** token.

The token travels in the **`Authorization` header**, not the body — so it
stays out of request-body logs and is cleanly separated from the payload.

```jsonc
// request
// Header: Authorization: Bearer 3f9a…64hex…
{
  "address": "bc1q…",
  "workers": [
    { "worker": "rig1", "extranonce": "c0debabe" },
    { "worker": "rig2", "extranonce": "c0debabf" }
  ]
}
```

```jsonc
// 200 response
{
  "address": "bc1q…",
  "updated": [
    { "worker": "rig1", "extranonce": "c0debabe" },
    { "worker": "rig2", "extranonce": "c0debabf" }
  ],
  "updatedAt": 1730000000000
}
```

**All or nothing.** Every entry lands or none does — a half-applied batch
would leave your fleet in a state you never asked for. If any entry is
rejected, nothing is written and the error names the problem.

**Swapping prefixes between your own workers is allowed.** Sending
`rig1 := rig2's prefix` and `rig2 := rig1's prefix` in one batch works: the
uniqueness rule is checked at the end of the request, so a temporary
in-request collision is fine. Two workers left on the **same** prefix is
still rejected.

Limits: at least 1 and at most **256** workers per request; no repeated
worker and no repeated prefix within one request.

---

## Prefix format & reserved range

- 8 hex characters (a `0x` prefix is accepted and ignored), case-insensitive.
- Allowed range: **`0x02000000` – `0xFFFFFFFF`**.
- **`0x00……` and `0x01……` are rejected** (`reserved-extranonce-range`). Those
  top bytes are the partitions the SV2 and SV1 servers allocate from
  automatically, so a value there could later be handed to another miner. Values
  from `0x02……` up are never auto-allocated, so they are yours exclusively.

That leaves ~99 % of the space. If you need a value in `0x00……`/`0x01……`, you
can't — pick anything from `0x02000000` on.

---

## When the EN is used

- **At channel-open.** The override applies when your miner opens an Extended
  channel — i.e. when it connects or reconnects. Set the override **before** the
  miner connects and it is baked into the first job.
- **Live, without reconnect.** If the connection was already carrying an override
  when it opened (it is then "armed"), a new value you set via the API lands at
  the **next job/template** — within one cache refresh (~10 s) plus the next
  template. No reconnect needed.
- **Caveat — the first override needs a connect.** If your miner is already
  connected with **no** override when you set the very first one, it won't apply
  until the miner reconnects (the connection is armed at channel-open). After
  that first one, further changes are live. In practice: set your initial
  override before starting the miner, then change it freely while it runs.
- **Your old EN stays valid during a switch.** Each job remembers the prefix it
  went out under, so shares still in flight for the previous job are accepted —
  no rejected-share burst at the moment of change.
- **Not retroactive on a block-change job.** When a new block appears the pool
  builds and sends the block job to every miner in milliseconds — long before
  your script can react and call the API. Your new value therefore lands on the
  **next** job after your call, not on that block's first job.

---

## Solo-only

The feature only works while mining **Solo**, because a non-Solo (PPLNS /
Group-Solo / Blockparty) miner does not hash its own dedicated coinbase, so a
custom prefix there could overlap another miner's search space.

- The API rejects addresses it can tell are non-Solo — members of a group /
  Group-Solo / Blockparty, or an address currently mining in the PPLNS window —
  with `409 not-solo-mode`. This is checked both when issuing the challenge and
  on every `set`.
- A non-grouped address that mines PPLNS purely by connecting on a PPLNS port
  can't be detected at write time, but the core still refuses to apply the
  override on a non-Solo connection and logs a warning. Either way the override
  never applies off Solo.

---

## No collision check (by design)

There is **no cross-address collision check**, and this is intentional and safe:

- The pool is non-custodial, so in Solo every address hashes a coinbase with its
  **own** payout outputs. Two **different** addresses using the **same** prefix
  therefore produce different block headers — they can never overlap. Enforcing
  global prefix uniqueness would reject harmless cases for no reason.

What **is** enforced, and what isn't:

- **Enforced:** `UNIQUE (address, prefix)`. One address may **not** point two of
  its own workers at the same prefix — in Solo that would collapse their search
  spaces and waste hashrate. Violating it returns `409 extranonce-in-use`.
  *Swapping* two of your workers' prefixes in one batch is fine (see
  [`set`](#3-post-apiaddressextranonceset)) — what's rejected is two workers
  actually ending up on the same prefix.
- **Not enforced (your footgun):** the override is per `(address, worker)`, but
  the extranonce is per **connection**. If you run **two physical devices under
  the same `address.worker`**, both receive the same prefix and grind the same
  space — they collide with each other. Give each device a **distinct worker
  name** and list them all in one `set` request.
- **Multi-channel connections:** only the **primary** (first) channel of a
  connection receives the override; any additional channels keep their distinct
  pool-allocated prefixes. An aggregating proxy therefore never collapses, but
  the custom value applies to one of its channels only.

---

## Current limitations

- **Solo mode only** (see above).
- **SV2 Extended channels only.** A Standard channel (SV1-translated or
  `REQUIRES_STANDARD_JOBS` firmware) does not receive the override; the core logs
  a warning if one is set for such a worker.
- **Primary channel only** on multi-channel connections (see above).
- **First-override-needs-connect** arming caveat (see
  [When the EN is used](#when-the-en-is-used)).
- **~10 s propagation.** The core polls Postgres every 10 s, so a change is not
  instant; it lands within one interval plus the next template.
- **No revert-to-allocated over the wire.** Clearing an override affects the
  worker at its next reconnect; a live connection keeps the last value until then.

---

## Error codes

| HTTP | `code`                     | Meaning                                                            |
|------|----------------------------|--------------------------------------------------------------------|
| 400  | `invalid-extranonce`       | prefix isn't 8 hex chars                                            |
| 400  | `reserved-extranonce-range`| prefix top byte is `0x00`/`0x01`                                    |
| 400  | `missing-signature`        | empty signature when requesting a token                            |
| 400  | `invalid-signature`        | signature doesn't verify against the stored challenge message      |
| 400  | `empty-batch`              | `workers` was empty                                                |
| 400  | `batch-too-large`          | more than 256 workers in one request                               |
| 400  | `duplicate-worker-in-batch`| the same worker appears twice in one request                       |
| 400  | `duplicate-extranonce-in-batch` | two workers in one request claim the same prefix              |
| 401  | `missing-token`            | no `Authorization: Bearer` header on `set`                         |
| 401  | `no-token`                 | no token has been issued for this address                          |
| 401  | `invalid-token`            | token doesn't match the stored hash                                |
| 404  | `no-challenge`             | token request with no pending challenge for the address           |
| 409  | `not-solo-mode`            | address is (determinably) not mining Solo                          |
| 409  | `extranonce-in-use`        | this address already points another worker at that prefix          |
| 410  | `challenge-expired`        | the challenge is older than 15 minutes                             |

---

## Typical flow

```
One-time, to get a token:
1. POST /api/address/extranonce/challenge {address}
        → sign the returned `message` with the address key
2. POST /api/address/extranonce/token     {address, signature}
        → 200: store the returned `token` (shown only once)

Any time, one or many workers at once (reuse the token):
3. POST /api/address/extranonce/set   Authorization: Bearer <token>
                                      {address, workers:[{worker, extranonce}, …]}
        → 200: all overrides stored (or none, on any error)

4. (Re)start the miner authorising as `address.worker` on a Solo port,
   opening an SV2 Extended channel
        → the core applies the prefix on the first job
5. To change a worker while running: repeat step 3 with a new value; it lands
   at the next template (armed connection), no reconnect.

Lost the token, or want to rotate it? Repeat steps 1–2 — the new token
replaces (revokes) the old one.
```
