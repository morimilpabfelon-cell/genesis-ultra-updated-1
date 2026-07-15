import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const GENERATED_ARTIFACTS = path.join(os.tmpdir(), `genesis-ultra-transfer-${process.pid}.json`);
const BACKUP_RECOVERY_ARTIFACTS = path.join(
  os.tmpdir(),
  `genesis-ultra-backup-recovery-${process.pid}.json`
);
const TRANSACTION_CRASH_ARTIFACTS = path.join(
  os.tmpdir(),
  `genesis-ultra-transaction-crash-${process.pid}.json`
);

process.on("exit", () => {
  fs.rmSync(GENERATED_ARTIFACTS, { force: true });
  fs.rmSync(BACKUP_RECOVERY_ARTIFACTS, { force: true });
  fs.rmSync(TRANSACTION_CRASH_ARTIFACTS, { force: true });
});

function resolvePython() {
  const candidates = process.platform === "win32" ? ["py", "python"] : ["python3", "python"];
  for (const candidate of candidates) {
    const result = spawnSync(candidate, ["--version"], { cwd: ROOT, encoding: "utf8" });
    if (result.status === 0) return candidate;
  }
  throw new Error("Python 3 no encontrado. Instala Python 3.12+ y vuelve a ejecutar npm test.");
}

const python = resolvePython();
const commands = [
  ["Validate workspace (Python)", python, ["tools/validate_workspace.py"]],
  [
    "Validate draft integrity manifest (Python)",
    python,
    ["tools/generate_draft_manifest.py", "--check"]
  ],
  ["Validate workspace (Node)", process.execPath, ["tools/validate_workspace.mjs"]],
  [
    "Validate live observer boundaries",
    process.execPath,
    ["--test", "observer/test/core.test.mjs"]
  ],
  ["Validate immutable birth identity (Python)", python, ["tools/validate_instance_identity.py"]],
  [
    "Validate immutable birth identity independently (Node)",
    process.execPath,
    ["tools/validate_instance_identity.mjs"]
  ],
  ["Validate signed sense observations (Python)", python, ["tools/validate_sense_observations.py"]],
  [
    "Validate signed sense observations independently (Node)",
    process.execPath,
    ["tools/validate_sense_observations.mjs"]
  ],
  [
    "Validate associative memory projection (Python)",
    python,
    ["tools/validate_associative_memory_projection.py"]
  ],
  [
    "Validate associative memory projection independently (Node)",
    process.execPath,
    ["tools/validate_associative_memory_projection.mjs"]
  ],
  [
    "Validate deterministic memory retrieval (Python)",
    python,
    ["tools/validate_memory_retrieval.py"]
  ],
  [
    "Validate deterministic memory retrieval independently (Node)",
    process.execPath,
    ["tools/validate_memory_retrieval.mjs"]
  ],
  ["Validate neutral sense adapters (Python)", python, ["tools/validate_sense_adapters.py"]],
  [
    "Validate neutral sense adapters independently (Node)",
    process.execPath,
    ["tools/validate_sense_adapters.mjs"]
  ],
  ["Validate continuity vectors", python, ["tools/validate_continuity.py"]],
  ["Validate neutral host contract (Python)", python, ["tools/validate_host_adapter.py"]],
  [
    "Validate neutral host contract independently (Node)",
    process.execPath,
    ["tools/validate_host_adapter.mjs"]
  ],
  [
    "Validate protocol vectors independently (Node)",
    process.execPath,
    ["tools/validate_protocol_vectors.mjs"]
  ],
  ["Validate crypto vectors", python, ["tools/validate_crypto_vectors.py"]],
  ["Simulate transfer A -> B", python, ["tools/simulate_transfer.py", "--artifacts-output", GENERATED_ARTIFACTS]],
  [
    "Simulate committed backup and authorized recovery B -> C",
    python,
    [
      "tools/simulate_backup_recovery.py",
      "--source-artifacts",
      GENERATED_ARTIFACTS,
      "--artifacts-output",
      BACKUP_RECOVERY_ARTIFACTS
    ]
  ],
  [
    "Simulate transaction journal crash recovery",
    python,
    [
      "tools/simulate_transaction_crashes.py",
      "--transfer-artifacts",
      GENERATED_ARTIFACTS,
      "--recovery-artifacts",
      BACKUP_RECOVERY_ARTIFACTS,
      "--artifacts-output",
      TRANSACTION_CRASH_ARTIFACTS
    ]
  ],
  [
    "Validate generated artifacts",
    process.execPath,
    [
      "tools/validate_artifacts.mjs",
      GENERATED_ARTIFACTS,
      BACKUP_RECOVERY_ARTIFACTS,
      TRANSACTION_CRASH_ARTIFACTS
    ]
  ],
  ["Simulate transfer and authority negative cases", python, ["tools/simulate_negatives.py"]],
  [
    "Simulate backup and recovery negative cases",
    python,
    ["tools/simulate_backup_recovery_negatives.py", "--artifacts", BACKUP_RECOVERY_ARTIFACTS]
  ]
];

for (const [label, command, args] of commands) {
  console.log(`\n=== ${label} ===`);
  const result = spawnSync(command, args, { cwd: ROOT, stdio: "inherit" });
  if (result.error) {
    console.error(`FAIL ${label}: ${result.error.message}`);
    process.exit(1);
  }
  if (result.status !== 0) {
    console.error(`FAIL ${label}: exit ${result.status}`);
    process.exit(result.status ?? 1);
  }
}

console.log("\nGenesis Ultra conformance suite: OK");
console.log("Passing this suite does not make the draft production-ready.");
