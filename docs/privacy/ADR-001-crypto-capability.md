# ADR-001 — Cryptographic Capability Model for PII at Rest

**Track:** D1 — Privacy & Data Contracts
**Status:** Proposed (awaiting Themis gate + user final approval)
**Addresses findings:** R3 (PII at-rest), R7 (web/PWA crypto)
**Related:** ADR-002 (legacy plaintext quarantine), SPEC-01 (manifest), SPEC-03 (export envelope)

## 1. Context

Open3DCalc persists user data on three surfaces:

- **Electron desktop:** renderer state mirrored into a SQLite `storage` table via
  `db:get`/`db:set`/`db:delete`/`db:list-keys` IPC, plus the SQLite domain tables
  (`customers`, `quotes`, `quote_items`, `history_entries` — the single list is
  `PII_DOMAIN_TABLES` in `electron/piiDomainTables.ts`) under `userData`.
- **Web/PWA:** `localStorage` (Zustand `persist` and direct `localStorage` usage), plus
  potential IndexedDB/OPFS and Cache API surfaces used by the PWA/service worker.
- **Cross-device transfer:** the `dataSync.ts` encrypted bundle (already AES-256-GCM with
  PBKDF2-SHA256, 100k iterations — see SPEC-03 for the normative envelope).

Today, PII (customers, quotes with `customerSnapshot`) is written to these surfaces in
plaintext. This ADR defines the **capability model** that D1.1+ must implement so that no
platform ever has a plaintext PII path at rest.

## 2. Decision

### 2.1 Electron desktop

**Primary mechanism: `safeStorage` (Electron API).**

- On availability of `safeStorage` (`isEncryptionAvailable() === true`), every PII-bearing
  value (per SPEC-01: any manifest key with `pii: true`) MUST be encrypted with
  `safeStorage.encryptString()` before it is written to SQLite (`storage` table or domain
  tables) or to any file under `userData` (logs, snapshots, staging included).
- Decryption happens only in memory, at read time, via `safeStorage.decryptString()`.

**Fallback: encrypted-at-rest with a user passphrase — only when a passphrase is available.**

- If `safeStorage` is unavailable, the app MAY fall back to an envelope encryption scheme
  (AES-256-GCM with a key derived from a user-supplied passphrase via PBKDF2-SHA256, per
  SPEC-03 parameters) **only while a passphrase is held in memory**.
- The passphrase MUST NOT be persisted anywhere: not to disk, not to SQLite, not to
  `localStorage`, not to OS credential storage, not to logs. It lives in memory for the
  session only and is zeroized on lock/exit.
- Consequence: with this fallback, PII written in one session is only readable again after
  the user re-enters the passphrase. That is the intended trade-off.

**Deny path: no `safeStorage` AND no passphrase ⇒ PII persistence is DENIED.**

- If neither capability is available, the app MUST NOT persist PII at all. PII-bearing
  features degrade to in-memory-only (`persistence: "memory_only"` in SPEC-01 terms) or are
  disabled with an explicit user-facing explanation (i18n, per repo conventions). The app
  remains usable for non-PII data.

**Zero plaintext path.** There is no configuration, flag, or code path in which PII is written
unencrypted at rest. `plaintext_allowed` in SPEC-01 is valid **only** for keys with
`pii: false`, and the schema enforces this invariant structurally.

### 2.2 Web / PWA

- **Primary mechanism: Web Crypto API** (`crypto.subtle`), which requires a
  [secure context](https://developer.mozilla.org/docs/Web/Security/Secure_Contexts)
  (HTTPS or `localhost`).
- PII at rest on web MUST be encrypted with AES-256-GCM using a key derived from a
  user-supplied passphrase (PBKDF2-SHA256, SPEC-03 parameters). The passphrase is held in
  memory only (session lifetime), never persisted — not to `localStorage`, IndexedDB,
  cookies, or the service worker cache.
- **Insecure context (plain HTTP on a LAN IP, etc.) or no passphrase ⇒ PII is blocked.**
  The web build MUST NOT write PII to `localStorage`/IndexedDB/OPFS/Cache API in these
  conditions. Non-PII keys (preferences, flags, cache) continue to work normally.
- The PWA service worker MUST NOT cache PII-bearing responses or PII-bearing export
  artifacts. Cache API entries are covered by the erasure saga (SPEC-02) and by the
  manifest's `surface` field.

### 2.3 Capability decision table

The table below is normative for D1.1+ and is mirrored by SPEC-01's per-platform fields.
"PII persistence outcome" is the only allowed outcome for that row.

| Platform | `safeStorage` / Web Crypto | Passphrase (in memory) | PII persistence outcome                                        |
| -------- | -------------------------- | ---------------------- | -------------------------------------------------------------- |
| Electron | `safeStorage` available    | (not required)         | **Encrypted at rest** via `safeStorage`                        |
| Electron | `safeStorage` unavailable  | Available              | **Encrypted at rest** via passphrase envelope (SPEC-03 params) |
| Electron | `safeStorage` unavailable  | Not available          | **DENIED** — PII features degrade to `memory_only` or disabled |
| Web/PWA  | Secure context             | Available              | **Encrypted at rest** via Web Crypto + passphrase              |
| Web/PWA  | Secure context             | Not available          | **DENIED** — PII blocked (memory-only at most)                 |
| Web/PWA  | Insecure context           | (any)                  | **DENIED** — PII blocked; non-PII unaffected                   |

Notes:

- "Available" for a passphrase means the user has entered one in the current session and it
  is held in memory. There is no "remember passphrase" feature; that would be persistence.
- The deny path is fail-closed. A crash, capability probe failure, or ambiguous state
  resolves to DENIED, never to plaintext.
- Capability probing happens at startup and on demand; results are cached in memory only.

## 3. The authenticated-encryption contract (at-rest envelope)

The at-rest envelope is specified in `src/shared/lib/crypto/envelope.ts`. Its AAD is
the whole security contract, so it is written here as bytes, not prose.

### 3.1 The exact AAD byte string

The additional authenticated data is the UTF-8 encoding of five fields joined by a
single NUL (`U+0000`) each:

```
"open3dcalc-pii-at-rest" NUL <K> NUL <P> NUL "schema:<S>" NUL "envelope:<F>"
```

| Slot | Symbol | Meaning                                                               |
| ---- | ------ | --------------------------------------------------------------------- |
| 1    | —      | Domain separator: `open3dcalc-pii-at-rest`                            |
| 2    | `K`    | Storage key NAME (e.g. `open3dcalc_customers_v1`) — metadata, not PII |
| 3    | `P`    | Stable crypto-purpose identifier (e.g. `at-rest`)                     |
| 4    | `S`    | `schemaVersion` — logical schema of the protected value               |
| 5    | `F`    | `envelopeFormatVersion` — wire format of the sealed record            |

Constraints, all enforced by `validateEnvelopeExpectation`:

- `K` and `P` MUST NOT contain NUL. NUL is the only separator, so a NUL inside a
  component could make two different expectations serialise to identical bytes, and
  the AAD would then bind nothing. A NUL is rejected with `EnvelopeAadInvalidError`
  rather than producing an ambiguous AAD.
- `S` and `F` are **positive integers** serialised in canonical decimal: no sign, no
  leading zero, no exponent. One integer therefore has exactly one byte
  representation, and `1` can never mean something different from `01`.
- The byte string is a fixed layout, not a key-ordered JSON encoding. Sorting keys
  is what let the old binding be re-derived from the ciphertext; the offsets here
  are normative and are asserted in `__tests__/envelope.test.ts` against a
  hand-written literal.

### 3.2 Caller-trusted, never self-asserted

Decryption receives `K`, `P`, `S` and `F` from the trusted manifest/storage contract
and builds the AAD itself. **There is no decrypt overload that omits them.**

The envelope still carries the four values, but they are _unauthenticated metadata_:
they are compared against the caller's expectation and a mismatch is a rejection
(`metadata_mismatch`), and they are never used to derive the AAD. Consequently a
ciphertext copied under a different key, purpose, `S` or `F` fails GCM
authentication, independently in each of the four dimensions.

The defect this replaced: the reader took the key name from the ciphertext and
re-derived the AAD from it, so a ciphertext moved to another key decrypted cleanly,
and the production `decryptFromStorage(key, blob)` accepted its `key` argument and
discarded it.

### 3.3 Two version dimensions, and the envelope version

Three versions are in play and they are not interchangeable:

| Version | Type             | Changes when                                            |
| ------- | ---------------- | ------------------------------------------------------- |
| `v`     | envelope version | The sealed record's own format; dispatches the reader   |
| `F`     | positive integer | The envelope format the storage layer believes it wrote |
| `S`     | positive integer | The logical schema of the protected value               |

`S` and `F` are distinct axes on purpose: a value can keep its schema while the
sealed record changes shape, and a migration that bumps one must not silently bump
the other.

**`TODO(hermes)` — `S` is a constant, not a lookup, and a manifest `version` bump
is a live landmine.** The trusted source for `S` is the per-key `version` in the
SPEC-01 manifest, but `electron/cryptoCapability.ts:49-64` cannot reach the
fixture (node16 ESM output will not execute a static JSON import) and mirrors the
value as `PII_SCHEMA_VERSION = 1` instead. That mirror is safe only while nothing
else reads those `version` fields. It must become a per-key lookup, and the order
matters:

1. land the per-key lookup first, while every PII at-rest entry is still at
   version `1.0`/`1.1`/`1.2` — i.e. while the lookup returns what the constant
   already returns, so no envelope is affected;
2. only then allow a `version` bump on a PII at-rest entry.

Bump a `sqlite_domain_tables` (or any PII `encrypted_at_rest`) `version` while
`S` is still the constant, and on the day the lookup lands it silently re-labels
`S` for that key: every passphrase-sealed envelope already on disk fails GCM
authentication and becomes undecryptable. There is **no runtime signal** — no
migration, no counter, no log line, nothing that says "this key's schema version
moved"; the decryption path just throws `metadata_mismatch` on values that were
written correctly, and the bytes are still on disk and still intact. The
`safeStorage` branch is unaffected (it binds no AAD at all, §3.4), which is what
makes this so easy to miss in a test profile: the only values at risk are the
passphrase-sealed ones, which is exactly the fallback path.

This is a separate tracked item from the manifest work that makes it reachable:
`pii_stage`'s SPEC-01 declaration (§ Policy 1.5 → 1.6 in SPEC-04) is the first
edit to add a new PII at-rest `version` field, and it is deliberately left at
`1.0`. Pinned by `src/shared/lib/__tests__/piiStageDeclaration.test.ts` ("no PII
at-rest entry has moved off schema version 1"), which fails on the bump and names
this TODO. The `pii_stage` entry's own `purpose` carries the same warning, so it
is visible from the manifest as well as from here.

`v` selects a **version-specific reader**. The pre-remediation `1.1` envelope
authenticated `canonicalJson({purpose, key})` with both halves read back out of the
ciphertext, so its binding proved nothing about provenance, and it cannot be
re-authenticated under §3.1 — the tag covers the old bytes and cannot be re-signed.
The `1.1` reader therefore **fails closed and says so** (`legacy_self_asserted_aad`);
it is not silently reinterpreted as `2.0`. A live `1.1` value has to be re-encrypted
under `2.0` from a trusted read of the old envelope and the `1.1` blob deleted — a
storage-layer migration, not a crypto one. An unrecognised `v` is refused separately
(`unknown_envelope_version`) so an operator can tell "we can see this and cannot
trust it" from "this is from the future".

### 3.4 Key lifecycle

- **Passphrase (fallback path):** user-supplied, held in main-process memory for the
  session only, zeroized on lock/exit. Never persisted, never logged, never sent to
  argv/env. The at-rest key is derived per envelope from a fresh 128-bit salt at
  PBKDF2-SHA256 with exactly 310,000 iterations; there is no stored derived key to
  leak, rotate or revoke. Consequence: a value written in one session is unreadable
  until the passphrase is re-entered, which is the intended trade-off.
- **`safeStorage` (primary path):** the OS keyring owns the key; the app never sees
  or stores it. **Known limitation, stated rather than implied:** `safeStorage`
  exposes no associated-data parameter, so a `safeStorage` blob is bound to nothing —
  not to its storage key, purpose, `S` or `F`. Closing that needs a
  `safeStorage`-wrapped **profile data key** (a random per-profile key sealed by the
  OS keyring) with the application envelope layered on top. Until that exists, the
  `safeStorage` branch is protected by OS key availability and by the deny path, and
  by nothing else. Tracked as follow-up work, not as delivered.

### 3.5 KDF work factor — inconsistency, deliberately unresolved

Three PBKDF2-SHA256 work factors exist in the repo: 310,000 in `crypto/envelope.ts`
and in `exportEnvelope.ts` (the SPEC-03 value), and **100,000** in `dataSync.ts`,
which its own header documents as "100.000" and which it genuinely derives with. This
ADR retains the current factors and does **not** change them in the contract
remediation: a KDF parameter is not a value you can edit in place, since changing it
makes every existing ciphertext undecryptable. Bringing the 100,000 path to 310,000 is
separate, versioned work — a new envelope version, a read path that derives with the
declared factor rather than the compiled-in one, and a migration that re-encrypts
existing bundles. It is **out of scope here and still open.**

### 3.6 Version migration obligation — 1.1 envelopes now fail closed

**Status: NOT IMPLEMENTED. This is not a W1 deliverable.**

Bumping the envelope version is a data-affecting change, not a code-only one, and the
affected data is real: packaged Electron builds have run against real profiles, so a
live profile can hold `enc1:envelope:` rows written as `1.1`.

**Which stored shapes are affected**

| Stored shape                                                                                                                                      | Affected | Notes                                                                                                     |
| ------------------------------------------------------------------------------------------------------------------------------------------------- | -------- | --------------------------------------------------------------------------------------------------------- |
| `enc1:envelope:<json>` in the SQLite `storage` table (`key`/`value` columns) under a manifest `pii: true` key, in the Electron `userData` profile | **Yes**  | Written only when `safeStorage` was unavailable AND a session passphrase was held (ADR-001 §2.1, row 2.2) |
| `enc1:safeStorage:<base64>`                                                                                                                       | No       | Unaffected by this change — but see §3.4: it was never context-bound                                      |
| Domain tables `customers`, `quotes`, `quote_items`, `history_entries`                                                                             | No       | Not written through the envelope path                                                                     |
| Browser / PWA `localStorage`, IndexedDB, OPFS, Cache API                                                                                          | No       | The web build never calls the envelope path — see below                                                   |
| `dataSync.ts` / SPEC-03 export bundles                                                                                                            | No       | A different format with its own AAD (`canonicalJson`), untouched here                                     |

**Reachability in the web build: none.** `enc1:envelope:` is produced in exactly one
place, `electron/cryptoCapability.ts`, which runs only in the Electron main process.
The shared capability decision engine (`crypto/capability.ts`) is pure and has no
platform injection on web, and no module under `src/platform/web/**` imports the
envelope. The web row of the §2.3 table is still a _contract_, not an implementation:
the web build writes PII to `localStorage` **unencrypted**, which is the §6 gap and is
unaffected by this change. A browser profile therefore cannot contain an
`enc1:envelope:` row.

**What happens to an affected row now.** The versioned reader recognises `1.1` and
refuses it with `legacy_self_asserted_aad`. That is fail-closed by design — the `1.1`
AAD cannot be re-authenticated under §3.1 — but the operational consequence is that
those values are currently unreadable by the app.

**Recovery: copy-and-verify, never delete.**

1. Read the `1.1` value **through a `1.1`-capable reader that still honours its own
   self-asserted AAD**, holding the result only in memory. That reader must be
   quarantined to this migration and must not become the general read path — the
   defect this ADR remediates is precisely that self-assertion.
2. Re-encrypt that plaintext under `2.0` using the caller-trusted expectation for its
   key, purpose, `S` and `F`.
3. **Verify** the `2.0` envelope decrypts back to the same plaintext, then write it
   alongside.
4. Only after verification may the `1.1` blob be removed — and the copy-then-verify
   order is not negotiable: overwriting or deleting a `1.1` blob in place destroys the
   only copy of a value that may not be recoverable from any other source, since the
   passphrase fallback means it was never replicated anywhere else.

This matches the approved mode in which legacy sources are retained as **disclosed
residue** rather than silently purged; the migration must report what it moved and
what it left behind. A value that cannot be decrypted (wrong or absent passphrase,
corrupt `1.1` blob) must be surfaced to the user as unrecoverable, not dropped.

**Not implemented.** The contract remediation changes only the reader. No migration
code, no quarantine reader, no telemetry and no UI exist. Any window in which a `1.1`
value is unreadable is therefore still open, and this section is the tracking
obligation for it — not a description of shipped behaviour.

## 4. Consequences

- **Positive:** no plaintext PII at rest on any supported platform; a stolen SQLite file,
  `localStorage` dump, or `userData` directory does not yield customer data without the
  OS-backed key or the passphrase; a ciphertext cannot be silently relocated between
  keys, purposes or schema generations; the model is testable (TEST-MATRIX §2, §3).
- **Negative:** without `safeStorage` and without a passphrase, PII features are degraded —
  this is an accepted, explicit trade-off in favor of confidentiality; passphrase fallback
  means PII is unreadable across sessions until the passphrase is re-entered.
- **Migration:** existing plaintext PII does NOT silently become encrypted. It enters the
  quarantine regime of ADR-002 until migrated or eliminated by explicit user action.
  Existing `1.1` envelopes likewise fail closed and require the §3.3 re-encryption.
- **Cost:** a caller that supplies a wrong `S` or `F` loses access to its own data. That
  is the intended failure mode, and it is why those two values belong to the storage
  contract rather than to a constant inside the crypto module.

## 5. What this ADR explicitly does NOT claim

- **This is application-level encryption of current logical values.** It protects a
  value as it sits in the store right now. It is not a claim about the whole profile.
- **It is not protection against an unlocked-runtime compromise.** While a session is
  unlocked — or a passphrase is in main-process memory — the plaintext exists in
  memory and is reachable by anything running as the user. The contract is about what
  the _stored bytes_ are bound to, not about defending a live process.
- **It is not secure erasure of historical copies.** Encrypting a value now says
  nothing about copies that already exist: SQLite WAL/journal residue, `userData`
  backups, OS-level snapshots, diagnostic bundles, previously exported bundles, and
  copies the user has already made. Erasure is SPEC-02's job, and it can only be as
  good as its enumeration of the surfaces that hold copies.
- **It does not make the `safeStorage` path context-bound.** See §3.4.
- **It does not resolve the KDF inconsistency.** See §3.5.

## 6. What D1.0 does NOT deliver

This ADR is a contract for D1.1+. As of D1.0, the runtime still writes PII in plaintext and
`db:export` still copies a raw SQLite file; those are the gaps this ADR obligates D1.1+ to
close. Nothing in this document claims that behavior is already implemented.

## 7. Compliance trace

- R3 → §2.1 (deny path, zero plaintext), §2.3 table rows 3.
- R7 → §2.2 (web/PWA secure context + passphrase, blocked otherwise), §2.3 rows 4–6.
- Cross-device context binding → §3.1, §3.2.
- Cross-references: SPEC-01 (`persistence` enum, `plaintext_allowed` ⇔ `pii:false`, and
  the per-key `version` that is the trusted source of `S`), SPEC-02 (snapshot encryption
  uses the same capability model), SPEC-03 (export envelope parameters),
  TEST-MATRIX §2 (capability matrix tests), §3 (deny-path tests).

## Status

**Status: Proposed (awaiting Themis gate + user final approval)**
