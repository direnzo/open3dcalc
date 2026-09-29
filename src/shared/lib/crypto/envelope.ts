/**
 * At-rest passphrase envelope (D1.1 S2) — ADR-001 §2.1/§2.2/§2.4.
 *
 * AES-256-GCM with a key derived from a user passphrase, using the normative
 * SPEC-03 envelope parameters: PBKDF2-SHA256 with exactly 310,000 iterations
 * (OWASP 2023), 128-bit random salt, 96-bit random IV and a 128-bit tag.
 *
 * ## The AAD is the whole security contract
 *
 * AES-GCM authenticates the additional authenticated data, so the AAD — not
 * anything inside the envelope — is what stops a ciphertext from being moved
 * somewhere it does not belong. The AAD is one unambiguous byte string:
 *
 *   UTF-8( "open3dcalc-pii-at-rest" NUL <K> NUL <P> NUL "schema:<S>" NUL "envelope:<F>" )
 *
 *  - `K` — the storage key NAME (names are metadata, never PII).
 *  - `P` — a stable crypto-purpose identifier.
 *  - `S` — `schemaVersion`, the logical schema of the value being protected.
 *  - `F` — `envelopeFormatVersion`, the wire format of the sealed record.
 *
 * `S` and `F` are two DISTINCT caller-trusted positive integers. They are
 * separate axes: a value can keep its schema (`S`) while the sealed record
 * changes shape (`F`), and a migration that bumps one must not silently bump
 * the other. Both are serialised in canonical decimal (no sign, no leading
 * zero) so that one integer has exactly one byte representation.
 *
 * `K` and `P` MUST NOT contain NUL. NUL is the only separator, so a NUL inside
 * a component could make two different expectations produce identical bytes —
 * `validateEnvelopeExpectation` rejects that instead of emitting an ambiguous
 * AAD.
 *
 * ## Caller-trusted, never self-asserted
 *
 * Decryption receives `K`/`P`/`S`/`F` from the trusted manifest/storage
 * contract and builds the AAD itself. The identity fields carried inside the
 * envelope are UNAUTHENTICATED metadata: they are compared against the
 * caller's expectation and a mismatch is a rejection, but they are never used
 * to derive the AAD. The pre-remediation defect was exactly that: the reader
 * took the key name from the ciphertext and re-derived the AAD from it, so a
 * ciphertext copied to another key decrypted cleanly.
 *
 * The passphrase is held in memory only for the session (ADR-001 §2.1); this
 * module never persists it, never derives to a stored key, and never logs
 * plaintext or key material. Relies only on the Web Crypto API
 * (globalThis.crypto.subtle), so the same module runs in the Electron main
 * process, the web renderer, and tests.
 */

/**
 * Domain-separation label. Part of the on-disk byte contract: changing it makes
 * every existing at-rest envelope undecryptable, so it is a versioned value,
 * not a cosmetic one.
 */
export const AAD_DOMAIN = "open3dcalc-pii-at-rest";

/** Crypto purpose for the primary at-rest PII envelope (the `P` component). */
export const AT_REST_PURPOSE = "at-rest";

/** Envelope version written by this module. Dispatches the reader. */
export const ENVELOPE_VERSION = "2.0";

/**
 * The pre-remediation envelope: its AAD was `canonicalJson({purpose, key})` and
 * both halves of that AAD were read back out of the ciphertext itself. Kept as
 * a READABLE version so the reader can recognise it and refuse it explicitly,
 * instead of the old blanket "unknown version" refusal that gave no reason.
 */
export const LEGACY_ENVELOPE_VERSION = "1.1";

/** The `F` component this build writes (`CURRENT_ENVELOPE_FORMAT_VERSION`). */
export const CURRENT_ENVELOPE_FORMAT_VERSION = 1;

/** SPEC-03: iterations are exactly 310,000. Unchanged by this remediation —
 *  see the KDF-inconsistency note at the bottom of this file. */
export const PBKDF2_ITERATIONS = 310_000;

const SALT_BYTES = 16; // 128-bit
const IV_BYTES = 12; // 96-bit
const KEY_BITS = 256;

/**
 * The caller-trusted expectation. Every field comes from the storage contract
 * (which manifest key, which purpose, which schema) — never from the envelope.
 */
export interface EnvelopeExpectation {
  /** `K` — storage key NAME the payload belongs to (names are metadata). */
  key: string;
  /** `P` — stable crypto-purpose identifier. */
  purpose: string;
  /** `S` — logical schema version of the protected value. */
  schemaVersion: number;
  /** `F` — envelope format version of the sealed record. */
  envelopeFormatVersion: number;
}

/**
 * Unauthenticated identity block carried in the envelope. Present for
 * diagnostics and for the consistency check; it is NOT an input to the AAD.
 */
export type EnvelopeMeta = EnvelopeExpectation;

export interface AtRestEnvelope {
  v: typeof ENVELOPE_VERSION;
  kdf: { alg: "PBKDF2-SHA256"; it: number; salt: string };
  cipher: { alg: "AES-256-GCM"; iv: string };
  meta: EnvelopeMeta;
  ct: string;
}

/**
 * Single rejection type: tamper, wrong passphrase, a moved ciphertext and
 * parameter drift are all "rejected" — the message is identical in every case
 * so a caller cannot use the failure as an oracle (SPEC-03 §7.3 principle).
 *
 * `reason` is a static code, not a value: every site below passes a
 * compile-time constant, so no plaintext, key material, key name or version
 * reaches it. It exists because a versioned reader is useless to operators if
 * "refused" and "never heard of this version" are the same string — and it
 * does not weaken the indistinguishability guarantee, which is about the
 * message and the type, both of which stay uniform.
 */
export type EnvelopeRejectionReason =
  /** The caller handed us nothing to derive a key from. */
  | "password_required"
  /** Not JSON, not an object, or a structurally invalid field. */
  | "malformed_envelope"
  /** `v` is not a version this build has a reader for. */
  | "unknown_envelope_version"
  /** `v` is known, but its AAD is not caller-trusted and cannot be recovered. */
  | "legacy_self_asserted_aad"
  /** Declared KDF/cipher parameters do not match what `v` requires. */
  | "parameter_drift"
  /** Envelope metadata disagrees with the caller's expectation. */
  | "metadata_mismatch"
  /** GCM refused: wrong passphrase, moved ciphertext, or tampered bytes. */
  | "authentication_failed";

export class EnvelopeRejectedError extends Error {
  readonly reason: EnvelopeRejectionReason;
  constructor(reason: EnvelopeRejectionReason) {
    super("envelope rejected");
    this.name = "EnvelopeRejectedError";
    this.reason = reason;
  }
}

/** Why an expectation is unusable. Always a caller bug, never a data problem. */
export type EnvelopeAadFault =
  | "key_contains_nul"
  | "purpose_contains_nul"
  | "schema_version_not_positive_integer"
  | "envelope_format_version_not_positive_integer";

/**
 * A caller passed an expectation that cannot produce an unambiguous AAD.
 *
 * Deliberately a DIFFERENT type from `EnvelopeRejectedError`: a NUL in the
 * key name is a programming error in the caller, and folding it into the
 * indistinguishable rejection would hide a bug that will corrupt every
 * envelope it touches.
 */
export class EnvelopeAadInvalidError extends Error {
  readonly reason: EnvelopeAadFault;
  constructor(reason: EnvelopeAadFault) {
    super(`envelope aad is ambiguous (${reason})`);
    this.name = "EnvelopeAadInvalidError";
    this.reason = reason;
  }
}

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

function fromHex(hex: string, expectedBytes: number): Uint8Array<ArrayBuffer> {
  if (!/^[0-9a-f]+$/.test(hex) || hex.length !== expectedBytes * 2) {
    throw new EnvelopeRejectedError("malformed_envelope");
  }
  const out = new Uint8Array(new ArrayBuffer(expectedBytes));
  for (let i = 0; i < expectedBytes; i++) {
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

function toBase64(bytes: Uint8Array): string {
  let binary = "";
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary);
}

function fromBase64(b64: string): Uint8Array<ArrayBuffer> {
  const binary = atob(b64);
  const out = new Uint8Array(new ArrayBuffer(binary.length));
  for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
  return out;
}

function isPositiveInteger(value: unknown): value is number {
  return (
    typeof value === "number" &&
    Number.isInteger(value) &&
    value > 0 &&
    value <= Number.MAX_SAFE_INTEGER
  );
}

/**
 * Reject an expectation that cannot produce an unambiguous AAD.
 *
 * Two failure classes, both silent-corruption risks if skipped:
 *  - NUL inside `K` or `P` would let two different expectations serialise to
 *    the same bytes, so the AAD would bind nothing.
 *  - a non-canonical integer (`0`, `-1`, `1.5`, `NaN`, `1e21`) would either be
 *    unserialisable or would stringify to something other than the integer the
 *    caller believes it named (`1e21`, `-0`).
 */
export function validateEnvelopeExpectation(
  expectation: EnvelopeExpectation,
): void {
  if (typeof expectation.key !== "string" || expectation.key.includes("\0")) {
    throw new EnvelopeAadInvalidError("key_contains_nul");
  }
  if (
    typeof expectation.purpose !== "string" ||
    expectation.purpose.includes("\0")
  ) {
    throw new EnvelopeAadInvalidError("purpose_contains_nul");
  }
  if (!isPositiveInteger(expectation.schemaVersion)) {
    throw new EnvelopeAadInvalidError("schema_version_not_positive_integer");
  }
  if (!isPositiveInteger(expectation.envelopeFormatVersion)) {
    throw new EnvelopeAadInvalidError(
      "envelope_format_version_not_positive_integer",
    );
  }
}

/**
 * The exact AAD byte string. See the module header for the byte layout; the
 * four components are joined by a single NUL and the two versions by their
 * labels, so the encoding is unambiguous in both directions.
 */
export function buildAadBytes(
  expectation: EnvelopeExpectation,
): Uint8Array<ArrayBuffer> {
  validateEnvelopeExpectation(expectation);
  return new TextEncoder().encode(
    `${AAD_DOMAIN}\0${expectation.key}\0${expectation.purpose}\0` +
      `schema:${expectation.schemaVersion}\0` +
      `envelope:${expectation.envelopeFormatVersion}`,
  );
}

function subtle(): SubtleCrypto {
  const c = globalThis.crypto;
  if (!c?.subtle) throw new EnvelopeRejectedError("authentication_failed");
  return c.subtle;
}

function randomBytes(n: number): Uint8Array<ArrayBuffer> {
  const out = new Uint8Array(new ArrayBuffer(n));
  globalThis.crypto.getRandomValues(out);
  return out;
}

async function deriveKey(
  passphrase: string,
  salt: Uint8Array<ArrayBuffer>,
  iterations: number,
): Promise<CryptoKey> {
  const enc = new TextEncoder().encode(passphrase);
  const base = await subtle().importKey("raw", enc, "PBKDF2", false, [
    "deriveKey",
  ]);
  return subtle().deriveKey(
    {
      name: "PBKDF2",
      salt: salt,
      iterations: iterations,
      hash: "SHA-256",
    },
    base,
    { name: "AES-GCM", length: KEY_BITS },
    false,
    ["encrypt", "decrypt"],
  );
}

async function aesGcm(
  operation: "encrypt" | "decrypt",
  key: CryptoKey,
  iv: Uint8Array<ArrayBuffer>,
  aad: Uint8Array<ArrayBuffer>,
  data: Uint8Array<ArrayBuffer>,
): Promise<ArrayBuffer> {
  return subtle()[operation](
    { name: "AES-GCM", iv: iv, additionalData: aad, tagLength: 128 },
    key,
    data,
  );
}

/**
 * Encrypt `plaintext` into an at-rest envelope JSON string.
 *
 * `expectation` MUST come from the storage contract. It is validated before
 * any cryptography runs, so an ambiguous expectation can never produce an
 * envelope that some other expectation would also open.
 */
export async function encryptWithPassphrase(
  plaintext: string,
  passphrase: string,
  expectation: EnvelopeExpectation,
): Promise<string> {
  validateEnvelopeExpectation(expectation);
  if (passphrase.length === 0) {
    throw new EnvelopeRejectedError("password_required");
  }
  const salt = randomBytes(SALT_BYTES);
  const iv = randomBytes(IV_BYTES);
  const key = await deriveKey(passphrase, salt, PBKDF2_ITERATIONS);
  const ct = await aesGcm(
    "encrypt",
    key,
    iv,
    buildAadBytes(expectation),
    new TextEncoder().encode(plaintext),
  );
  const envelope: AtRestEnvelope = {
    v: ENVELOPE_VERSION,
    kdf: { alg: "PBKDF2-SHA256", it: PBKDF2_ITERATIONS, salt: toHex(salt) },
    cipher: { alg: "AES-256-GCM", iv: toHex(iv) },
    meta: { ...expectation },
    ct: toBase64(new Uint8Array(ct)),
  };
  return JSON.stringify(envelope);
}

type EnvelopeRecord = Record<string, unknown>;

type VersionReader = (
  env: EnvelopeRecord,
  passphrase: string,
  expectation: EnvelopeExpectation,
  iterations: number,
) => Promise<string>;

/**
 * The 1.1 reader.
 *
 * A 1.1 envelope authenticated `canonicalJson({purpose, key})` with BOTH halves
 * read back out of the ciphertext, so the binding proved nothing about where
 * the ciphertext actually came from. There is no way to re-authenticate an
 * existing 1.1 envelope under the caller-trusted AAD — the tag covers the old
 * bytes and cannot be re-signed — so the only honest outcome is to fail closed
 * and say why. It is routed here rather than lumped in with "unknown version"
 * so that an operator can tell "we can see this and it cannot be trusted" from
 * "this is from the future".
 *
 * Migration for a live 1.1 value: re-encrypt it under 2.0 from a trusted read
 * of the old envelope, then delete the 1.1 blob. That is a storage-layer job,
 * not a crypto one. **The planned migration is specified in ADR-001 §3.6 and is
 * NOT implemented.** Read that section before acting on this error: the
 * prescribed order is copy-then-verify-then-remove, because silently deleting
 * or overwriting a 1.1 blob destroys the only copy of that value — the
 * passphrase fallback never replicated it anywhere else. A packaged build has
 * run against a real profile, so this is not hypothetical.
 */
const readLegacyV11: VersionReader = () => {
  throw new EnvelopeRejectedError("legacy_self_asserted_aad");
};

const META_FIELDS = [
  "key",
  "purpose",
  "schemaVersion",
  "envelopeFormatVersion",
] as const;

function readMeta(env: EnvelopeRecord): EnvelopeMeta {
  const meta = env.meta;
  if (typeof meta !== "object" || meta === null || Array.isArray(meta)) {
    throw new EnvelopeRejectedError("malformed_envelope");
  }
  const record = meta as Record<string, unknown>;
  // Exact shape: an unknown or missing field means this record was not written
  // by a contract we understand, and guessing which field is missing is exactly
  // the "do not reinterpret" failure the versioned reader exists to prevent.
  if (Object.keys(record).length !== META_FIELDS.length) {
    throw new EnvelopeRejectedError("malformed_envelope");
  }
  for (const field of META_FIELDS) {
    if (!(field in record)) {
      throw new EnvelopeRejectedError("malformed_envelope");
    }
  }
  if (
    typeof record.key !== "string" ||
    typeof record.purpose !== "string" ||
    !isPositiveInteger(record.schemaVersion) ||
    !isPositiveInteger(record.envelopeFormatVersion)
  ) {
    throw new EnvelopeRejectedError("malformed_envelope");
  }
  return {
    key: record.key,
    purpose: record.purpose,
    schemaVersion: record.schemaVersion,
    envelopeFormatVersion: record.envelopeFormatVersion,
  };
}

function metaMatches(
  meta: EnvelopeMeta,
  expected: EnvelopeExpectation,
): boolean {
  return (
    meta.key === expected.key &&
    meta.purpose === expected.purpose &&
    meta.schemaVersion === expected.schemaVersion &&
    meta.envelopeFormatVersion === expected.envelopeFormatVersion
  );
}

/**
 * The 2.0 reader: the AAD is built from the caller's expectation, full stop.
 * The envelope's own metadata is compared to it and nothing more.
 */
const readV2: VersionReader = async (
  env,
  passphrase,
  expectation,
  iterations,
) => {
  const kdf = env.kdf;
  const cipher = env.cipher;
  if (
    typeof kdf !== "object" ||
    kdf === null ||
    typeof cipher !== "object" ||
    cipher === null
  ) {
    throw new EnvelopeRejectedError("malformed_envelope");
  }
  const kdfRecord = kdf as Record<string, unknown>;
  const cipherRecord = cipher as Record<string, unknown>;
  // Parameters are declared by the VERSION, not by the ciphertext: a record
  // that names a different work factor is refused rather than derived with.
  if (kdfRecord.alg !== "PBKDF2-SHA256" || kdfRecord.it !== iterations) {
    throw new EnvelopeRejectedError("parameter_drift");
  }
  if (cipherRecord.alg !== "AES-256-GCM") {
    throw new EnvelopeRejectedError("parameter_drift");
  }
  if (typeof env.ct !== "string") {
    throw new EnvelopeRejectedError("malformed_envelope");
  }
  const meta = readMeta(env);
  if (!metaMatches(meta, expectation)) {
    throw new EnvelopeRejectedError("metadata_mismatch");
  }
  const salt = fromHex(String(kdfRecord.salt), SALT_BYTES);
  const iv = fromHex(String(cipherRecord.iv), IV_BYTES);
  const key = await deriveKey(passphrase, salt, iterations);
  try {
    const pt = await aesGcm(
      "decrypt",
      key,
      iv,
      buildAadBytes(expectation),
      fromBase64(env.ct),
    );
    return new TextDecoder().decode(pt);
  } catch {
    throw new EnvelopeRejectedError("authentication_failed");
  }
};

interface EnvelopeVersionSpec {
  readonly iterations: number;
  readonly read: VersionReader;
}

/**
 * The versioned reader. Dispatch is on `v` and nothing else — a record whose
 * version is not in this table is refused, never attempted under a nearby
 * version's rules.
 */
const READERS: Readonly<Record<string, EnvelopeVersionSpec>> = {
  [LEGACY_ENVELOPE_VERSION]: {
    iterations: PBKDF2_ITERATIONS,
    read: readLegacyV11,
  },
  [ENVELOPE_VERSION]: { iterations: PBKDF2_ITERATIONS, read: readV2 },
};

/**
 * Decrypt an at-rest envelope.
 *
 * `expectation` is the caller's TRUSTED statement of where this ciphertext is
 * supposed to live. It is mandatory: there is deliberately no overload that
 * decrypts without one, because "read the key name out of the ciphertext" is
 * the defect this module was remediated for.
 */
export async function decryptWithPassphrase(
  envelopeJson: string,
  passphrase: string,
  expectation: EnvelopeExpectation,
): Promise<string> {
  validateEnvelopeExpectation(expectation);
  let parsed: unknown;
  try {
    parsed = JSON.parse(envelopeJson);
  } catch {
    throw new EnvelopeRejectedError("malformed_envelope");
  }
  if (typeof parsed !== "object" || parsed === null) {
    throw new EnvelopeRejectedError("malformed_envelope");
  }
  const env = parsed as EnvelopeRecord;
  const version = typeof env.v === "string" ? env.v : null;
  const spec = version === null ? undefined : READERS[version];
  if (!spec) throw new EnvelopeRejectedError("unknown_envelope_version");
  return spec.read(env, passphrase, expectation, spec.iterations);
}

// ---------------------------------------------------------------------------
// Retained utility: the SPEC-03 EXPORT envelope (exportEnvelope.ts) and the
// consent-receipt hash still canonicalise JSON with this, and it is part of the
// published SPEC-03 wire format. It is no longer the at-rest AAD — see the
// module header.
// ---------------------------------------------------------------------------

/** Canonical JSON (sorted keys, no whitespace) — RFC 8785 (JCS) equivalent. */
export function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) {
    return `[${value.map(canonicalJson).join(",")}]`;
  }
  const entries = Object.entries(value as Record<string, unknown>)
    .filter(([, v]) => v !== undefined)
    .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
    .map(([k, v]) => `${JSON.stringify(k)}:${canonicalJson(v)}`);
  return `{${entries.join(",")}}`;
}

/*
 * KDF inconsistency — REPORTED, deliberately not changed here.
 *
 * The repo derives passphrase keys at two different work factors:
 *   - this module and exportEnvelope.ts: PBKDF2-SHA256 @ 310,000 (SPEC-03).
 *   - dataSync.ts: PBKDF2-SHA256 @ 100,000, documented as "100.000" in its
 *     header and used for the real derivation.
 *
 * The remediation plan retains the current KDF, so nothing is changed in this
 * commit. Bringing the 100,000 path to 310,000 is a separate, versioned piece
 * of work: it changes a key-derivation parameter, so it cannot be a silent
 * edit. It needs its own envelope version, a re-derive-on-read path, and a
 * migration that re-encrypts existing bundles.
 */
