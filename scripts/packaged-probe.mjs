#!/usr/bin/env node
/**
 * W6 packaged keyring-probe harness — see docs/privacy/BETA5-RELEASE-EVIDENCE.md §6.
 *
 * Packages a minimal Electron shell whose only entry point is the compiled
 * `electron/selftest/packaged-probe.ts`, runs it HEADLESS against the packaged
 * binary, and asserts the §3.4 keyring gate behaved as the gate says it does.
 *
 * Why a separate packaged shell instead of the product bundle: the product
 * `--dir` build drags in the renderer bundle and better-sqlite3 (a native
 * rebuild against the packaged Electron ABI) to answer a question that needs
 * neither. `electron-builder.probe.yml` packages the same compiled
 * `osKeyring.js` / `cryptoCapability.js` the application ships, in a real
 * `app.asar` under a real packaged Electron runtime. That is a shell, and the
 * evidence file states the limit rather than hiding it.
 *
 * Usage:
 *   node scripts/packaged-probe.mjs                  # build + run on this host
 *   node scripts/packaged-probe.mjs --no-build       # reuse an existing package
 *   node scripts/packaged-probe.mjs --image ubuntu:24.04
 *   node scripts/packaged-probe.mjs --image host     # explicit host run
 *
 * Exit code 0 only when a report was produced AND every invariant below held.
 * No secrets, no PII and no paths are printed: the report itself is value-free
 * by construction and this script only adds booleans and version strings.
 */

import { execFileSync, spawnSync } from "node:child_process";
import { existsSync, readdirSync, statSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(here, "..");

const PREFIX = "__PACKAGED_PROBE__";
const PROBE_OUTPUT_DIR = path.join(repoRoot, "dist-electron-probe");
const PROBE_CONFIG = "electron-builder.probe.yml";
const EXECUTABLE_NAME = "open3dcalc-keyring-probe";
const CONTAINER_ENTRY = path.join(
  repoRoot,
  "scripts",
  "packaged-probe-container.sh",
);

/** The four names the §3.4 allowlist accepts, mirrored for the assertion. */
const EXPECTED_ALLOWLIST = [
  "gnome_libsecret",
  "kwallet",
  "kwallet5",
  "kwallet6",
];

/**
 * Home-path prefixes the value-free report must never contain, one per OS:
 * Linux `/home/` and `/root/`, macOS `/Users/`, Windows `C:\Users\` (which
 * `JSON.stringify` writes as the escaped `C:\\Users\\`).
 */
const FORBIDDEN_PATH_MARKERS = [
  "/home/",
  "/root/",
  "/Users/",
  "C:\\\\Users\\\\",
];

/** Every refusal code `probeOsKeyring` can return. */
const KNOWN_REFUSALS = new Set([
  "encryption_unavailable",
  "backend_probe_missing",
  "backend_probe_failed",
  "backend_basic_text",
  "backend_unknown",
  "backend_not_allowlisted",
  "os_round_trip_failed",
  "unsupported_platform",
]);

function parseArgs(argv) {
  const options = { build: true, image: null };
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === "--no-build") options.build = false;
    else if (arg === "--image") options.image = argv[++i] ?? null;
    else if (arg.startsWith("--image=")) options.image = arg.slice(8);
    else {
      console.error(`[packaged-probe] unknown argument: ${arg}`);
      process.exit(2);
    }
  }
  // `--image host` is the explicit spelling of "no container"; the CI matrix
  // uses it so the baseline runner is a matrix row like any other.
  if (options.image === "host" || options.image === "") options.image = null;
  return options;
}

function run(command, args, extra = {}) {
  return spawnSync(command, args, {
    cwd: repoRoot,
    encoding: "utf8",
    ...extra,
  });
}

function build() {
  console.log("[packaged-probe] compiling the Electron main bundle…");
  execFileSync("npx", ["tsc", "-p", "electron/tsconfig.json"], {
    cwd: repoRoot,
    stdio: "inherit",
  });

  console.log("[packaged-probe] packaging the probe shell (--dir)…");
  const res = run("npx", [
    "electron-builder",
    "--linux",
    "--dir",
    "--config",
    PROBE_CONFIG,
    "--publish",
    "never",
  ]);
  if (res.status !== 0) {
    console.error(res.stdout ?? "");
    console.error(res.stderr ?? "");
    throw new Error(`electron-builder exited with status ${res.status}`);
  }
}

/** The packaged binary, under whichever `linux*-unpacked` dir was produced. */
function locateProbeBinary() {
  if (!existsSync(PROBE_OUTPUT_DIR)) {
    throw new Error(
      `no packaged output at ${path.relative(repoRoot, PROBE_OUTPUT_DIR)} — run without --no-build first`,
    );
  }
  const direct = path.join(PROBE_OUTPUT_DIR, "linux-unpacked", EXECUTABLE_NAME);
  if (existsSync(direct)) return direct;

  for (const entry of readdirSync(PROBE_OUTPUT_DIR, { withFileTypes: true })) {
    if (!entry.isDirectory() || !entry.name.startsWith("linux")) continue;
    const candidate = path.join(PROBE_OUTPUT_DIR, entry.name, EXECUTABLE_NAME);
    if (existsSync(candidate) && statSync(candidate).isFile()) return candidate;
  }
  throw new Error(
    `packaged probe executable '${EXECUTABLE_NAME}' not found under dist-electron-probe/`,
  );
}

/** Electron in a container/headless runner: no sandbox, no X, no GPU. */
const HEADLESS_ARGS = [
  "--no-sandbox",
  "--disable-gpu",
  "--disable-dev-shm-usage",
  "--ozone-platform=headless",
];

function reportFrom(stdout) {
  const lines = (stdout ?? "")
    .split("\n")
    .filter((line) => line.startsWith(PREFIX));
  if (lines.length === 0) return null;
  return JSON.parse(lines[lines.length - 1].slice(PREFIX.length + 1));
}

/**
 * Run the probe on this host. Three strategies, in order, because a headless
 * runner and a developer's desktop need different ones and neither should have
 * to know about the other: direct, ozone-headless, then xvfb-run when present.
 */
function runOnHost(binary) {
  const attempts = [
    { command: binary, args: HEADLESS_ARGS },
    { command: binary, args: ["--no-sandbox", "--disable-gpu"] },
  ];
  const xvfb = run("which", ["xvfb-run"]);
  if (xvfb.status === 0) {
    attempts.push({
      command: "xvfb-run",
      args: ["-a", binary, "--no-sandbox", "--disable-gpu"],
    });
  }

  const failures = [];
  for (const attempt of attempts) {
    const res = run(attempt.command, attempt.args, { timeout: 60_000 });
    const report = reportFrom(res.stdout);
    if (report) return { report, via: path.basename(attempt.command) };
    failures.push(
      `${path.basename(attempt.command)}: ${(res.stderr ?? "").trim().slice(0, 300) || "no report"}`,
    );
  }
  throw new Error(`probe produced no report: ${failures.join(" | ")}`);
}

/**
 * Run the probe inside a distro container. The packaged directory and the
 * dependency-installing entry script are mounted read-only; nothing is written
 * outside the container.
 */
function runInContainer(binary, image) {
  // `binary` is …/dist-electron-probe/linux-unpacked/<executable>, so the
  // directory to mount is its immediate parent (…/linux-unpacked) — the
  // packaged shell's own directory, with the executable at its root.
  const probeDir = path.dirname(binary);
  const containerBinary = `/probe/${EXECUTABLE_NAME}`;
  const res = run(
    "docker",
    [
      "run",
      "--rm",
      "--volume",
      `${probeDir}:/probe:ro`,
      "--volume",
      `${CONTAINER_ENTRY}:/probe-entry.sh:ro`,
      image,
      "bash",
      "/probe-entry.sh",
      containerBinary,
      ...HEADLESS_ARGS,
    ],
    { timeout: 600_000 },
  );
  const report = reportFrom(res.stdout);
  if (!report) {
    console.error(res.stdout ?? "");
    console.error(res.stderr ?? "");
    throw new Error(
      `probe produced no report inside ${image} (docker status ${res.status})`,
    );
  }
  return { report, via: image };
}

/**
 * The invariants. Each one fails when the gate stops doing what ADR-001 §3.4
 * claims it does.
 *
 * Honest scope of what CI exercises: every matrix row runs without a D-Bus
 * session bus or a keyring, so the observed verdict is always `denied` /
 * `encryption_unavailable`. CI therefore falsifies the REFUSAL path plus the
 * packaging/coherence invariants below (allowlist identity, capability ↔ gate
 * agreement, value-free report). It does NOT exercise the ACCEPTANCE path — the
 * branch where `basic_text` is refused while a real keyring is accepted. That
 * branch is pinned by the unit test `electron/__tests__/osKeyring.test.ts`,
 * which mocks `safeStorage`; a green harness run is not evidence that the gate
 * accepts a real keyring.
 */
function assertReport(report) {
  const problems = [];
  const check = (ok, message) => {
    if (!ok) problems.push(message);
  };

  check(
    report.schema === "open3dcalc.packaged-keyring-probe/v1",
    "schema mismatch",
  );
  check(report.error === undefined, `probe reported an error: ${report.error}`);

  // 1. It really ran from a packaged bundle. Without this the whole exercise is
  //    just the dev self-test wearing a different name.
  check(report.packaged?.isPackaged === true, "app.isPackaged is not true");
  check(report.packaged?.asar === true, "app path is not an app.asar");

  // 2. The allowlist the gate applied is EXACTLY the four documented names —
  //    not a superset. `osKeyring.ts` treats a grown allowlist as a new threat
  //    model ("an allowlist that grows by accident is not an allowlist"), so a
  //    fifth name must fail here instead of slipping past an `includes` check.
  const allowlist = Array.isArray(report.allowlist) ? report.allowlist : [];
  const expectedAllowlist = [...EXPECTED_ALLOWLIST].sort();
  const actualAllowlist = [...allowlist].sort();
  check(
    actualAllowlist.length === expectedAllowlist.length &&
      actualAllowlist.every((name, index) => name === expectedAllowlist[index]),
    `allowlist is not exactly the four documented backends (${EXPECTED_ALLOWLIST.join(", ")})`,
  );

  // 3. The gate's verdict is internally consistent, in both directions.
  const keyring = report.keyring ?? {};
  if (keyring.available === true) {
    check(
      allowlist.includes(keyring.backend),
      `gate accepted a backend outside the allowlist: ${keyring.backend}`,
    );
    // The exact defect §3.4 exists to stop: `basic_text` is obfuscation, and a
    // probe that accepted it would report a customer's name as encrypted on a
    // machine where it is not.
    check(
      keyring.backend !== "basic_text",
      "gate accepted the basic_text backend",
    );
  } else {
    check(
      typeof keyring.reason === "string" && KNOWN_REFUSALS.has(keyring.reason),
      `refusal code is not one the gate defines: ${keyring.reason}`,
    );
  }

  // 4. The §2.3 table agrees with the §3.4 gate. No passphrase is held by this
  //    process, so `safe_storage` is reachable only when the keyring passed.
  const capability = report.capability ?? {};
  check(
    capability.mode ===
      (keyring.available === true ? "safe_storage" : "denied"),
    `capability mode '${capability.mode}' disagrees with the keyring gate`,
  );
  check(
    report.verdict ===
      (capability.piiPersistence === "encrypted_at_rest"
        ? "encrypted_at_rest"
        : "denied"),
    "verdict disagrees with the capability table",
  );

  // 5. Evidence, not a claim: the raw probe and the round-trip are both
  //    reported, so a "denied" verdict can be told apart from a broken harness.
  check(
    typeof report.safeStorageAvailable === "boolean",
    "safeStorage raw probe missing",
  );
  check(typeof report.roundTrip === "boolean", "round-trip result missing");

  // 6. Value-free hygiene. A username in a home path, a blob, or key material
  //    in a log line is exactly what this probe must never produce. Home-path
  //    prefixes are checked for every OS the report can come from.
  const serialized = JSON.stringify(report);
  check(!serialized.includes("enc1:"), "report contains a ciphertext blob");
  for (const marker of FORBIDDEN_PATH_MARKERS) {
    check(
      !serialized.includes(marker),
      `report contains a filesystem path (${marker})`,
    );
  }
  check(
    !serialized.includes("open3dcalc-keyring-probe-0000"),
    "report contains the probe sentinel value",
  );

  return problems;
}

function summarize(report, via, problems) {
  const distro = report.distro
    ? `${report.distro.id} ${report.distro.versionId}`.trim()
    : "unknown";
  const keyring = report.keyring ?? {};
  const backend = keyring.available
    ? keyring.backend
    : `${keyring.reason}${keyring.reportedBackend ? ` (reported: ${keyring.reportedBackend})` : ""}`;

  console.log("");
  console.log(`  packaged probe — ${via}`);
  console.log(`  ├─ distro           ${distro}`);
  console.log(
    `  ├─ runtime          ${report.runtime?.platform}/${report.runtime?.arch}`,
  );
  console.log(
    `  ├─ electron         ${report.versions?.electron} (chrome ${report.versions?.chrome})`,
  );
  console.log(
    `  ├─ packaged         isPackaged=${report.packaged?.isPackaged} asar=${report.packaged?.asar}`,
  );
  console.log(
    `  ├─ safeStorage      ${report.safeStorageAvailable} (raw probe, NOT the gate)`,
  );
  console.log(`  ├─ keyring gate     ${backend}`);
  console.log(`  ├─ sentinel round-trip ${report.roundTrip}`);
  console.log(
    `  ├─ capability       ${report.capability?.mode} → ${report.capability?.reason}`,
  );
  console.log(`  └─ verdict          ${report.verdict}`);
  console.log("");

  if (problems.length > 0) {
    for (const problem of problems) console.error(`  ✗ ${problem}`);
    return false;
  }
  console.log("  ✓ every packaged-probe invariant held");
  return true;
}

function main() {
  const options = parseArgs(process.argv.slice(2));

  if (options.build) build();
  const binary = locateProbeBinary();

  const { report, via } = options.image
    ? runInContainer(binary, options.image)
    : runOnHost(binary);

  console.log(`${PREFIX} ${JSON.stringify(report)}`);
  const ok = summarize(report, via, assertReport(report));
  process.exit(ok ? 0 : 1);
}

main();
