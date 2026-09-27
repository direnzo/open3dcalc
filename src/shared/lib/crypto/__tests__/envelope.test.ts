/**
 * Contract tests for the at-rest authenticated-encryption envelope.
 *
 * The AAD contract is the point of this file, so the exact byte string is
 * asserted as a HAND-WRITTEN LITERAL byte array. A test that rebuilds the
 * expectation with `buildAadBytes(...)` proves only that the function is
 * idempotent — if the contract itself were wrong, such a test would stay
 * green forever. The literal below is the specification; the production
 * builder must match it byte for byte.
 *
 * Synthetic fixtures only, never real PII. Real Web Crypto, no mocks
 * (TEST-MATRIX §0).
 */

import { describe, it, expect } from "vitest";
import {
  encryptWithPassphrase,
  decryptWithPassphrase,
  buildAadBytes,
  validateEnvelopeExpectation,
  canonicalJson,
  PBKDF2_ITERATIONS,
  ENVELOPE_VERSION,
  LEGACY_ENVELOPE_VERSION,
  CURRENT_ENVELOPE_FORMAT_VERSION,
  AT_REST_PURPOSE,
  type EnvelopeExpectation,
  EnvelopeRejectedError,
  EnvelopeAadInvalidError,
} from "@/shared/lib/crypto/envelope";

const PASS = "sessão-sintética-de-teste-3131";
const PLAINTEXT = "Fernanda Sintética <fernanda@exemplo.teste>";

const EXPECTATION: EnvelopeExpectation = {
  key: "open3dcalc_customers_v1",
  purpose: AT_REST_PURPOSE,
  schemaVersion: 1,
  envelopeFormatVersion: CURRENT_ENVELOPE_FORMAT_VERSION,
};

/**
 * UTF-8 of the AAD contract for EXPECTATION, spelled out by hand:
 *
 *   "open3dcalc-pii-at-rest" \0 "open3dcalc_customers_v1" \0 "at-rest"
 *   \0 "schema:1" \0 "envelope:1"
 *
 * 74 bytes; the four NUL separators sit at offsets 22, 46, 54 and 63.
 */
const EXPECTED_AAD_BYTES = [
  111, 112, 101, 110, 51, 100, 99, 97, 108, 99, 45, 112, 105, 105, 45, 97, 116,
  45, 114, 101, 115, 116, 0, 111, 112, 101, 110, 51, 100, 99, 97, 108, 99, 95,
  99, 117, 115, 116, 111, 109, 101, 114, 115, 95, 118, 49, 0, 97, 116, 45, 114,
  101, 115, 116, 0, 115, 99, 104, 101, 109, 97, 58, 49, 0, 101, 110, 118, 101,
  108, 111, 112, 101, 58, 49,
];

function envelopeOf(blob: string): Record<string, unknown> {
  return JSON.parse(blob) as Record<string, unknown>;
}

function withMeta(
  envelope: Record<string, unknown>,
  patch: Partial<Record<string, unknown>>,
): string {
  return JSON.stringify({
    ...envelope,
    meta: { ...(envelope.meta as object), ...patch },
  });
}

/** Re-stamp the unauthenticated header so it agrees with a wrong caller
 * expectation — isolates the GCM binding from the metadata comparison. */
function restampAndSwap(
  blob: string,
  patch: Partial<EnvelopeExpectation>,
  envelopePatch: Record<string, unknown> = {},
): string {
  const env = envelopeOf(blob);
  return JSON.stringify({
    ...env,
    ...envelopePatch,
    meta: { ...(env.meta as object), ...patch },
  });
}

async function reasonOf(promise: Promise<unknown>): Promise<string> {
  const error = await promise.then(
    () => null,
    (e: unknown) => e,
  );
  expect(error).toBeInstanceOf(EnvelopeRejectedError);
  return (error as EnvelopeRejectedError).reason;
}

// ---------------------------------------------------------------------------
// 1. The exact AAD byte string.
// ---------------------------------------------------------------------------
describe("AAD byte contract (ADR-001 §2.4)", () => {
  it("builds the exact byte string, asserted against a hand-written literal", () => {
    expect(Array.from(buildAadBytes(EXPECTATION))).toEqual(EXPECTED_AAD_BYTES);
    expect(buildAadBytes(EXPECTATION).length).toBe(74);
  });

  it("separates every field with a single NUL at a known offset", () => {
    const bytes = buildAadBytes(EXPECTATION);
    const nulOffsets: number[] = [];
    for (let i = 0; i < bytes.length; i++) {
      if (bytes[i] === 0) nulOffsets.push(i);
    }
    expect(nulOffsets).toEqual([22, 46, 54, 63]);
    // Each component sits in its own slot — no field can be shifted into a
    // neighbour's bytes without moving a separator.
    const decoder = new TextDecoder();
    expect(decoder.decode(bytes.slice(0, 22))).toBe("open3dcalc-pii-at-rest");
    expect(decoder.decode(bytes.slice(23, 46))).toBe("open3dcalc_customers_v1");
    expect(decoder.decode(bytes.slice(47, 54))).toBe("at-rest");
    expect(decoder.decode(bytes.slice(55, 63))).toBe("schema:1");
    expect(decoder.decode(bytes.slice(64, 74))).toBe("envelope:1");
  });

  it("binds all four components independently into distinct byte strings", () => {
    const base = Array.from(buildAadBytes(EXPECTATION));
    // Same-length substitutions, so a length assertion cannot pass by accident.
    const variants: EnvelopeExpectation[] = [
      { ...EXPECTATION, key: "open3dcalc_customers_v2" },
      { ...EXPECTATION, purpose: "erasure" },
      { ...EXPECTATION, schemaVersion: 2 },
      { ...EXPECTATION, envelopeFormatVersion: 2 },
    ];
    for (const variant of variants) {
      const bytes = Array.from(buildAadBytes(variant));
      expect(bytes.length).toBe(base.length);
      expect(bytes).not.toEqual(base);
    }
    // The two version slots are single decimal digits: bumping either changes
    // exactly one byte, and never a separator.
    for (const variant of variants.slice(2)) {
      const bytes = Array.from(buildAadBytes(variant));
      expect(bytes.filter((b, i) => b !== base[i]).length).toBe(1);
      expect(bytes[22]).toBe(0);
      expect(bytes[46]).toBe(0);
      expect(bytes[54]).toBe(0);
      expect(bytes[63]).toBe(0);
    }
  });

  it("serialises versions in canonical decimal — no sign, no leading zero", () => {
    // 1 and 01 must be the same integer and therefore the same byte string;
    // a leading zero would silently produce a DIFFERENT, ambiguous AAD, so the
    // integer is validated rather than stringified blindly.
    expect(() => buildAadBytes({ ...EXPECTATION, schemaVersion: 0 })).toThrow(
      EnvelopeAadInvalidError,
    );
    expect(() => buildAadBytes({ ...EXPECTATION, schemaVersion: -1 })).toThrow(
      EnvelopeAadInvalidError,
    );
    expect(() =>
      buildAadBytes({ ...EXPECTATION, envelopeFormatVersion: 1.5 }),
    ).toThrow(EnvelopeAadInvalidError);
    expect(() =>
      buildAadBytes({ ...EXPECTATION, schemaVersion: Number.NaN }),
    ).toThrow(EnvelopeAadInvalidError);
    expect(() =>
      buildAadBytes({
        ...EXPECTATION,
        schemaVersion: Number.POSITIVE_INFINITY,
      }),
    ).toThrow(EnvelopeAadInvalidError);
  });

  it("rejects NUL in the key or the purpose instead of building an ambiguous AAD", () => {
    expect(() =>
      validateEnvelopeExpectation({
        ...EXPECTATION,
        key: "open3dcalc_customers_v1\u0000evil",
      }),
    ).toThrow(EnvelopeAadInvalidError);
    expect(() =>
      validateEnvelopeExpectation({
        ...EXPECTATION,
        purpose: "at-rest\u0000export",
      }),
    ).toThrow(EnvelopeAadInvalidError);
  });

  it("rejects a NUL split that would alias two different expectations", () => {
    // Without the NUL check these two would produce identical bytes:
    //   {key: "a\0b", purpose: "p"}   and   {key: "a", purpose: "b\0p"}
    expect(() => buildAadBytes({ ...EXPECTATION, key: "a\u0000b" })).toThrow(
      EnvelopeAadInvalidError,
    );
    expect(() =>
      buildAadBytes({ ...EXPECTATION, purpose: "bCleaning" }),
    ).not.toThrow();
  });

  it("names the offending field so the caller can fix it", () => {
    try {
      validateEnvelopeExpectation({ ...EXPECTATION, key: "bad\u0000key" });
      expect.unreachable("NUL in key must be rejected");
    } catch (error) {
      expect(error).toBeInstanceOf(EnvelopeAadInvalidError);
      expect((error as EnvelopeAadInvalidError).reason).toBe(
        "key_contains_nul",
      );
    }
  });
});

// ---------------------------------------------------------------------------
// 2. Round trip + header shape.
// ---------------------------------------------------------------------------
describe("round trip (SPEC-03 parameters, ADR-001)", () => {
  it("round-trips plaintext through a real AES-256-GCM envelope", async () => {
    const blob = await encryptWithPassphrase(PLAINTEXT, PASS, EXPECTATION);
    expect(blob).not.toContain(PLAINTEXT);
    expect(await decryptWithPassphrase(blob, PASS, EXPECTATION)).toBe(
      PLAINTEXT,
    );
  });

  it("records the normative SPEC-03 KDF/cipher parameters", async () => {
    const blob = await encryptWithPassphrase(PLAINTEXT, PASS, EXPECTATION);
    const env = envelopeOf(blob);
    expect(env.v).toBe(ENVELOPE_VERSION);
    const kdf = env.kdf as Record<string, unknown>;
    expect(kdf.alg).toBe("PBKDF2-SHA256");
    expect(kdf.it).toBe(PBKDF2_ITERATIONS);
    expect(kdf.it).toBe(310_000); // OWASP 2023 — retained, see the KDF report
    expect(String(kdf.salt)).toHaveLength(32); // 128-bit salt, hex
    const cipher = env.cipher as Record<string, unknown>;
    expect(cipher.alg).toBe("AES-256-GCM");
    expect(String(cipher.iv)).toHaveLength(24); // 96-bit IV, hex
  });

  it("carries the four identity components as UNAUTHENTICATED metadata", async () => {
    const blob = await encryptWithPassphrase(PLAINTEXT, PASS, EXPECTATION);
    expect(envelopeOf(blob).meta).toEqual({ ...EXPECTATION });
  });

  it("salt and IV are random per envelope (never reused)", async () => {
    const a = envelopeOf(
      await encryptWithPassphrase(PLAINTEXT, PASS, EXPECTATION),
    );
    const b = envelopeOf(
      await encryptWithPassphrase(PLAINTEXT, PASS, EXPECTATION),
    );
    expect((a.kdf as { salt: string }).salt).not.toBe(
      (b.kdf as { salt: string }).salt,
    );
    expect((a.cipher as { iv: string }).iv).not.toBe(
      (b.cipher as { iv: string }).iv,
    );
    expect(a.ct).not.toBe(b.ct);
  });

  it("rejects an empty passphrase before touching the KDF", async () => {
    expect(
      await reasonOf(encryptWithPassphrase(PLAINTEXT, "", EXPECTATION)),
    ).toBe("password_required");
  });
});

// ---------------------------------------------------------------------------
// 3. Each caller-trusted component fails independently.
// ---------------------------------------------------------------------------
describe("caller-trusted binding (a moved ciphertext must not decrypt)", () => {
  it("a ciphertext stamped for another key fails, even after re-stamping", async () => {
    const blob = await encryptWithPassphrase(PLAINTEXT, PASS, EXPECTATION);
    // (a) caller reads it under the wrong storage key, header untouched.
    await expect(
      decryptWithPassphrase(blob, PASS, {
        ...EXPECTATION,
        key: "open3dcalc_quotes_v1",
      }),
    ).rejects.toThrow(EnvelopeRejectedError);
    // (b) attacker re-stamps the header to agree with the wrong key: the GCM
    //     tag over the AAD is what stops it, not the metadata comparison.
    expect(
      await reasonOf(
        decryptWithPassphrase(
          restampAndSwap(blob, { key: "open3dcalc_quotes_v1" }),
          PASS,
          { ...EXPECTATION, key: "open3dcalc_quotes_v1" },
        ),
      ),
    ).toBe("authentication_failed");
  });

  it("a ciphertext stamped for another purpose fails independently", async () => {
    const blob = await encryptWithPassphrase(PLAINTEXT, PASS, EXPECTATION);
    expect(
      await reasonOf(
        decryptWithPassphrase(
          restampAndSwap(blob, { purpose: "export" }),
          PASS,
          { ...EXPECTATION, purpose: "export" },
        ),
      ),
    ).toBe("authentication_failed");
  });

  it("a ciphertext stamped for another schemaVersion fails independently", async () => {
    const blob = await encryptWithPassphrase(PLAINTEXT, PASS, EXPECTATION);
    expect(
      await reasonOf(
        decryptWithPassphrase(
          restampAndSwap(blob, { schemaVersion: 2 }),
          PASS,
          { ...EXPECTATION, schemaVersion: 2 },
        ),
      ),
    ).toBe("authentication_failed");
  });

  it("a ciphertext stamped for another envelopeFormatVersion fails independently", async () => {
    const blob = await encryptWithPassphrase(PLAINTEXT, PASS, EXPECTATION);
    expect(
      await reasonOf(
        decryptWithPassphrase(
          restampAndSwap(blob, { envelopeFormatVersion: 2 }),
          PASS,
          { ...EXPECTATION, envelopeFormatVersion: 2 },
        ),
      ),
    ).toBe("authentication_failed");
  });

  it("swapping exactly one component leaves the other three intact", async () => {
    const blob = await encryptWithPassphrase(PLAINTEXT, PASS, EXPECTATION);
    const swapped = restampAndSwap(blob, { schemaVersion: 7 });
    // The very same envelope still opens under the original expectation …
    expect(
      await reasonOf(decryptWithPassphrase(swapped, PASS, EXPECTATION)),
    ).toBe("metadata_mismatch");
    // … which is only possible because the AAD was built from the CALLER's
    // values, not from the (now tampered) header.
  });
});

// ---------------------------------------------------------------------------
// 4. Envelope metadata is compared, never trusted.
// ---------------------------------------------------------------------------
describe("envelope metadata is never self-asserted", () => {
  it("rejects metadata that disagrees with the caller's expectation", async () => {
    const blob = await encryptWithPassphrase(PLAINTEXT, PASS, EXPECTATION);
    for (const patch of [
      { key: "open3dcalc_quotes_v1" },
      { purpose: "export" },
      { schemaVersion: 2 },
      { envelopeFormatVersion: 2 },
    ]) {
      expect(
        await reasonOf(
          decryptWithPassphrase(
            withMeta(envelopeOf(blob), patch),
            PASS,
            EXPECTATION,
          ),
        ),
      ).toBe("metadata_mismatch");
    }
  });

  it("rejects a missing or malformed metadata block (fail closed)", async () => {
    const blob = await encryptWithPassphrase(PLAINTEXT, PASS, EXPECTATION);
    const env = envelopeOf(blob);
    const withoutMeta = JSON.stringify({ ...env, meta: undefined });
    expect(
      await reasonOf(decryptWithPassphrase(withoutMeta, PASS, EXPECTATION)),
    ).toBe("malformed_envelope");
    expect(
      await reasonOf(
        decryptWithPassphrase(
          JSON.stringify({ ...env, meta: { ...EXPECTATION, extra: "x" } }),
          PASS,
          EXPECTATION,
        ),
      ),
    ).toBe("malformed_envelope");
  });

  it("never derives the AAD from the envelope — proven by the re-stamp test", async () => {
    // If the AAD were rebuilt from `env.aad`/`env.meta` (the pre-remediation
    // defect at envelope.ts:198), this would decrypt successfully.
    const blob = await encryptWithPassphrase(PLAINTEXT, PASS, EXPECTATION);
    const env = envelopeOf(blob);
    const moved = JSON.stringify({
      ...env,
      meta: { ...EXPECTATION, key: "moved" },
    });
    await expect(
      decryptWithPassphrase(moved, PASS, EXPECTATION),
    ).rejects.toThrow(EnvelopeRejectedError);
  });
});

// ---------------------------------------------------------------------------
// 5. Ciphertext integrity + versioned reader.
// ---------------------------------------------------------------------------
describe("integrity and the versioned reader", () => {
  it("rejects an invalid tag indistinguishably from a wrong passphrase", async () => {
    const blob = await encryptWithPassphrase(PLAINTEXT, PASS, EXPECTATION);
    const env = envelopeOf(blob);
    env.ct = `${String(env.ct).slice(0, -2)}AA`;
    expect(
      await reasonOf(
        decryptWithPassphrase(JSON.stringify(env), PASS, EXPECTATION),
      ),
    ).toBe("authentication_failed");
    expect(
      await reasonOf(
        decryptWithPassphrase(
          blob,
          "outra-senha-totalmente-diferente",
          EXPECTATION,
        ),
      ),
    ).toBe("authentication_failed");
    await expect(
      decryptWithPassphrase(blob, "outra-senha", EXPECTATION),
    ).rejects.toThrow(/envelope rejected/);
  });

  it("rejects non-canonical, malformed and non-JSON input", async () => {
    const blob = await encryptWithPassphrase(PLAINTEXT, PASS, EXPECTATION);
    const env = envelopeOf(blob);
    (env.kdf as { it: number }).it = 100_000; // declared KDF drift
    expect(
      await reasonOf(
        decryptWithPassphrase(JSON.stringify(env), PASS, EXPECTATION),
      ),
    ).toBe("parameter_drift");
    const env2 = envelopeOf(blob);
    (env2.cipher as { iv: string }).iv = "zz";
    expect(
      await reasonOf(
        decryptWithPassphrase(JSON.stringify(env2), PASS, EXPECTATION),
      ),
    ).toBe("malformed_envelope");
    expect(
      await reasonOf(decryptWithPassphrase("not-json", PASS, EXPECTATION)),
    ).toBe("malformed_envelope");
  });

  it("rejects an unknown envelope version", async () => {
    const blob = await encryptWithPassphrase(PLAINTEXT, PASS, EXPECTATION);
    const env = envelopeOf(blob);
    env.v = "9.9";
    expect(
      await reasonOf(
        decryptWithPassphrase(JSON.stringify(env), PASS, EXPECTATION),
      ),
    ).toBe("unknown_envelope_version");
  });

  it("dispatches an older v to a version-specific path, not a blanket refuse", async () => {
    const blob = await encryptWithPassphrase(PLAINTEXT, PASS, EXPECTATION);
    const env = envelopeOf(blob);
    env.v = LEGACY_ENVELOPE_VERSION;
    // The reader RECOGNISES 1.1 and routes it to the 1.1 reader …
    expect(
      await reasonOf(
        decryptWithPassphrase(JSON.stringify(env), PASS, EXPECTATION),
      ),
    ).toBe("legacy_self_asserted_aad");
    // … which is a different outcome from "never heard of it".
    env.v = "9.9";
    expect(
      await reasonOf(
        decryptWithPassphrase(JSON.stringify(env), PASS, EXPECTATION),
      ),
    ).toBe("unknown_envelope_version");
  });

  it("fails a real 1.1 envelope closed instead of reinterpreting it as 2.0", async () => {
    // A genuine pre-remediation envelope: AES-256-GCM over
    // canonicalJson({purpose, key}) with the header asserted by itself.
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const base = await crypto.subtle.importKey(
      "raw",
      new TextEncoder().encode(PASS),
      "PBKDF2",
      false,
      ["deriveKey"],
    );
    const key = await crypto.subtle.deriveKey(
      { name: "PBKDF2", salt, iterations: PBKDF2_ITERATIONS, hash: "SHA-256" },
      base,
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt"],
    );
    const legacyAad = canonicalJson({
      purpose: "at-rest",
      key: EXPECTATION.key,
    });
    const ct = await crypto.subtle.encrypt(
      {
        name: "AES-GCM",
        iv,
        additionalData: new TextEncoder().encode(legacyAad),
      },
      key,
      new TextEncoder().encode(PLAINTEXT),
    );
    const legacy = JSON.stringify({
      v: LEGACY_ENVELOPE_VERSION,
      kdf: {
        alg: "PBKDF2-SHA256",
        it: PBKDF2_ITERATIONS,
        salt: Buffer.from(salt).toString("hex"),
      },
      cipher: { alg: "AES-256-GCM", iv: Buffer.from(iv).toString("hex") },
      aad: { purpose: "at-rest", key: EXPECTATION.key },
      ct: Buffer.from(ct).toString("base64"),
    });
    // It opens under the OLD contract …
    // … but not under the new one, and the refusal says why.
    expect(
      await reasonOf(decryptWithPassphrase(legacy, PASS, EXPECTATION)),
    ).toBe("legacy_self_asserted_aad");
  });

  it("every rejection carries a static reason, never a value", async () => {
    const blob = await encryptWithPassphrase(PLAINTEXT, PASS, EXPECTATION);
    try {
      await decryptWithPassphrase(blob, "senha-errada-9999", EXPECTATION);
      expect.unreachable("wrong passphrase must be rejected");
    } catch (error) {
      expect(error).toBeInstanceOf(EnvelopeRejectedError);
      expect((error as EnvelopeRejectedError).message).toBe(
        "envelope rejected",
      );
      expect((error as EnvelopeRejectedError).message).not.toContain(PASS);
      expect((error as EnvelopeRejectedError).message).not.toContain(PLAINTEXT);
      expect((error as EnvelopeRejectedError).message).not.toContain(
        EXPECTATION.key,
      );
    }
  });
});

// ---------------------------------------------------------------------------
// 6. canonicalJson survives as a utility (SPEC-03 export path depends on it).
// ---------------------------------------------------------------------------
describe("canonicalJson (retained utility, no longer the AAD)", () => {
  it("is stable and sorted", () => {
    expect(canonicalJson({ b: 1, a: 2 })).toBe('{"a":2,"b":1}');
    expect(canonicalJson({ a: { d: 1, c: [2, 1] } })).toBe(
      '{"a":{"c":[2,1],"d":1}}',
    );
    expect(canonicalJson({ a: undefined, b: null })).toBe('{"b":null}');
  });

  it("is NOT the at-rest AAD any more", async () => {
    const blob = await encryptWithPassphrase(PLAINTEXT, PASS, EXPECTATION);
    // The legacy AAD bytes are not accepted under the current contract: the
    // canonical-JSON binding is what allowed a moved ciphertext to decrypt.
    expect(
      await reasonOf(
        decryptWithPassphrase(
          JSON.stringify({ ...envelopeOf(blob), v: LEGACY_ENVELOPE_VERSION }),
          PASS,
          EXPECTATION,
        ),
      ),
    ).toBe("legacy_self_asserted_aad");
  });
});
