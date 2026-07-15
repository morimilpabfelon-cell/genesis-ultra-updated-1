import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const failures = [];

const WORKSPACE_MANIFEST = JSON.parse(
  fs.readFileSync(path.join(ROOT, "conformance/required_artifacts.json"), "utf8")
);
const REQUIRED = WORKSPACE_MANIFEST.required;
const FORBIDDEN = WORKSPACE_MANIFEST.forbidden;

function fail(message) {
  failures.push(message);
}

function readText(relativePath) {
  return fs.readFileSync(path.join(ROOT, relativePath), "utf8");
}

function readJson(relativePath) {
  return JSON.parse(readText(relativePath));
}

function walk(directory) {
  return fs.readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
    if ([".git", "node_modules"].includes(entry.name)) return [];
    const full = path.join(directory, entry.name);
    return entry.isDirectory() ? walk(full) : [full];
  });
}

function frame(value) {
  if (typeof value !== "string") throw new Error("field_must_be_string");
  if (value !== value.normalize("NFC")) throw new Error("text_not_nfc");
  const bytes = Buffer.from(value, "utf8");
  return Buffer.concat([
    Buffer.from(String(bytes.length) + ":", "ascii"),
    bytes,
    Buffer.from("\n", "ascii")
  ]);
}

function sha256(buffer) {
  return crypto.createHash("sha256").update(buffer).digest("hex");
}

function compareUtf8(left, right) {
  return Buffer.compare(Buffer.from(left, "utf8"), Buffer.from(right, "utf8"));
}

function computeSeedRoot(input) {
  const chunks = [
    frame("genesis.seed.root.v0.1"),
    frame(input.protocol_version),
    frame(input.seed_id),
    frame(input.identity_digest),
    frame(input.doctrine_digest)
  ];

  const files = [...input.files].sort((a, b) => compareUtf8(a.path, b.path));
  chunks.push(frame(String(files.length)));
  for (const file of files) {
    chunks.push(frame(file.path));
    chunks.push(frame(file.kind));
    chunks.push(frame(file.required ? "true" : "false"));
    chunks.push(frame(file.digest));
  }
  return "sha256:" + sha256(Buffer.concat(chunks));
}

function computeMemoryEventHash(input) {
  const order = [
    "schema_version",
    "event_id",
    "instance_id",
    "body_id",
    "sequence",
    "previous_event_hash",
    "event_type",
    "actor",
    "content_digest",
    "content_type",
    "observed_at",
    "provenance_digest",
    "privacy"
  ];
  const chunks = [frame("genesis.memory.event.v0.1")];
  for (const field of order) chunks.push(frame(field === "sequence" ? String(input[field]) : input[field]));
  return "evsha256:" + sha256(Buffer.concat(chunks));
}

function isSafePath(value) {
  if (typeof value !== "string" || value.length === 0) return false;
  if (value.includes("\u0000")) return false;
  if (value !== value.normalize("NFC")) return false;
  if (value.startsWith("/") || value.includes("\\")) return false;
  if (/^[A-Za-z]:/.test(value)) return false;
  const segments = value.split("/");
  return !segments.some((segment) => segment === "" || segment === "." || segment === "..");
}

function validateWorkspaceHygiene() {
  for (const [label, paths] of [["required", REQUIRED], ["forbidden", FORBIDDEN]]) {
    if (new Set(paths).size !== paths.length) fail(`duplicate_${label}_workspace_path`);
    if (paths.some((item, index) => item !== [...paths].sort(compareUtf8)[index])) {
      fail(`unsorted_${label}_workspace_paths`);
    }
    for (const relativePath of paths) {
      if (!isSafePath(relativePath)) fail(`unsafe_${label}_workspace_path:${relativePath}`);
    }
  }

  const forbiddenSet = new Set(FORBIDDEN);
  for (const relativePath of REQUIRED) {
    if (forbiddenSet.has(relativePath)) {
      fail(`required_and_forbidden_workspace_path:${relativePath}`);
    }
    if (!fs.existsSync(path.join(ROOT, relativePath))) {
      fail(`missing_required_file:${relativePath}`);
    }
  }

  for (const relativePath of FORBIDDEN) {
    if (fs.existsSync(path.join(ROOT, relativePath))) {
      fail(`forbidden_legacy_file:${relativePath}`);
    }
  }

  if (fs.existsSync(path.join(ROOT, ".git"))) {
    const result = spawnSync("git", ["ls-files", "-z"], { cwd: ROOT, encoding: "buffer" });
    if (result.status !== 0) {
      fail("tracked_file_inventory_unavailable");
    } else {
      const requiredSet = new Set(REQUIRED);
      const tracked = result.stdout
        .toString("utf8")
        .split("\0")
        .filter(Boolean)
        .filter((relativePath) => fs.existsSync(path.join(ROOT, relativePath)));
      for (const relativePath of tracked.sort()) {
        if (!requiredSet.has(relativePath)) fail(`unlisted_tracked_file:${relativePath}`);
      }
    }
  }

  for (const file of walk(ROOT).filter((item) => item.endsWith(".md"))) {
    const content = fs.readFileSync(file, "utf8");
    const linkPattern = /\[[^\]]+\]\(([^)\s]+)(?:\s+"[^"]*")?\)/g;
    for (const match of content.matchAll(linkPattern)) {
      const target = match[1];
      if (target.startsWith("#") || /^(?:https?|mailto):/i.test(target)) continue;

      let localTarget;
      try {
        localTarget = decodeURIComponent(target.split("#", 1)[0]);
      } catch {
        fail(`invalid_markdown_link:${path.relative(ROOT, file).replaceAll("\\", "/")}:${target}`);
        continue;
      }
      if (!localTarget) continue;

      const resolved = path.resolve(path.dirname(file), localTarget);
      const relativeToRoot = path.relative(ROOT, resolved);
      const displayFile = path.relative(ROOT, file).replaceAll("\\", "/");
      if (relativeToRoot === ".." || relativeToRoot.startsWith(`..${path.sep}`) || path.isAbsolute(relativeToRoot)) {
        fail(`markdown_link_outside_workspace:${displayFile}:${target}`);
      } else if (!fs.existsSync(resolved)) {
        fail(`broken_markdown_link:${displayFile}:${target}`);
      }
    }
  }
}

function computeDraftManifestRoot(manifest) {
  const fields = [
    manifest.schema_version,
    manifest.protocol_version,
    manifest.root_hash_profile,
    manifest.file_digest_algorithm,
    manifest.inventory_path,
    manifest.manifest_path,
    manifest.self_excluded ? "true" : "false",
    String(manifest.file_count)
  ];
  for (const record of manifest.files) {
    fields.push(record.path, String(record.size_bytes), record.digest);
  }
  const preimage = Buffer.concat([
    frame("genesis.draft.integrity.root.v0.1"),
    ...fields.map((value) => frame(value))
  ]);
  return `sha256:${sha256(preimage)}`;
}

function validateDraftManifest() {
  const manifest = readJson("conformance/draft_manifest.json");
  const expectedConstants = {
    schema_version: "genesis.draft.manifest.v0.1",
    protocol_version: "genesis.protocol.v0.1",
    root_hash_profile: "genesis.hash.fields.v0.1",
    file_digest_algorithm: "sha256",
    inventory_path: "conformance/required_artifacts.json",
    manifest_path: "conformance/draft_manifest.json",
    self_excluded: true
  };
  for (const [field, expected] of Object.entries(expectedConstants)) {
    if (manifest[field] !== expected) fail(`draft_manifest_${field}_invalid`);
  }

  if (REQUIRED.filter((item) => item === manifest.manifest_path).length !== 1) {
    fail("draft_manifest_path_must_be_required_once");
  }
  const expectedPaths = REQUIRED
    .filter((item) => item !== manifest.manifest_path)
    .sort(compareUtf8);
  const actualPaths = manifest.files.map((record) => record.path);
  if (manifest.file_count !== manifest.files.length || manifest.file_count !== expectedPaths.length) {
    fail("draft_manifest_file_count_mismatch");
  }
  if (new Set(actualPaths).size !== actualPaths.length) fail("draft_manifest_duplicate_path");
  if (actualPaths.some((item, index) => item !== expectedPaths[index])) {
    fail("draft_manifest_inventory_or_order_mismatch");
  }
  const forbiddenSet = new Set(FORBIDDEN);
  if (actualPaths.some((item) => forbiddenSet.has(item))) fail("draft_manifest_forbidden_path");

  for (const record of manifest.files) {
    const filePath = path.join(ROOT, record.path);
    if (!fs.existsSync(filePath)) {
      fail(`draft_manifest_missing_file:${record.path}`);
      continue;
    }
    const payload = fs.readFileSync(filePath);
    if (record.size_bytes !== payload.length) fail(`draft_manifest_size_mismatch:${record.path}`);
    const digest = `sha256:${sha256(payload)}`;
    if (record.digest !== digest) fail(`draft_manifest_digest_mismatch:${record.path}`);
  }

  if (manifest.root_digest !== computeDraftManifestRoot(manifest)) {
    fail("draft_manifest_root_digest_mismatch");
  }
}

validateWorkspaceHygiene();
validateDraftManifest();


// Paridad de comportamiento: toda implementacion debe RECHAZAR estos casos.
const behavior = JSON.parse(fs.readFileSync(path.join(ROOT, "conformance/behavior_cases.json"), "utf8"));
for (const c of behavior.must_reject_encoding) {
  let rejected = false;
  try { frame(c.value); } catch { rejected = true; }
  if (!rejected) fail(`encoding_no_rechazado:${c.case_id}`);
}
for (const c of behavior.must_reject_paths) {
  if (isSafePath(c.value)) fail(`ruta_no_rechazada:${c.case_id}`);
}

for (const file of walk(ROOT).filter((item) => item.endsWith(".json"))) {
  const relative = path.relative(ROOT, file).replaceAll("\\", "/");
  try {
    JSON.parse(fs.readFileSync(file, "utf8"));
  } catch (error) {
    fail(`invalid_json:${relative}:${error.message}`);
  }
}

for (const relativePath of REQUIRED.filter((item) => item.startsWith("schemas/"))) {
  if (!fs.existsSync(path.join(ROOT, relativePath))) continue;
  const schema = readJson(relativePath);
  if (schema.$schema !== "https://json-schema.org/draft/2020-12/schema") {
    fail(`wrong_schema_draft:${relativePath}`);
  }
  if (schema.type !== "object") fail(`schema_root_not_object:${relativePath}`);
  if (schema.additionalProperties !== false) fail(`schema_not_closed:${relativePath}`);
}

if (fs.existsSync(path.join(ROOT, "conformance/golden_vectors.json"))) {
  const vectors = readJson("conformance/golden_vectors.json");
  if (vectors.profile !== "genesis.hash.fields.v0.1") fail("wrong_golden_vector_profile");

  for (const testCase of vectors.field_encoding ?? []) {
    const actualHex = frame(testCase.value).toString("hex");
    if (actualHex !== testCase.expected_hex) {
      fail(`field_vector_mismatch:${testCase.case_id}:${actualHex}`);
    }
  }

  const seedActual = computeSeedRoot(vectors.seed_root.input);
  if (seedActual !== vectors.seed_root.expected_root_hash) {
    fail(`seed_root_vector_mismatch:${seedActual}`);
  }

  const eventActual = computeMemoryEventHash(vectors.memory_event.input);
  if (eventActual !== vectors.memory_event.expected_event_hash) {
    fail(`memory_event_vector_mismatch:${eventActual}`);
  }

  const manifestPaths = vectors.seed_root.input.files.map((item) => item.path);
  if (new Set(manifestPaths).size !== manifestPaths.length) fail("golden_seed_has_duplicate_paths");
  for (const manifestPath of manifestPaths) {
    if (!isSafePath(manifestPath)) fail(`golden_seed_has_unsafe_path:${manifestPath}`);
  }
}

if (fs.existsSync(path.join(ROOT, "conformance/invalid_cases.json"))) {
  const invalid = readJson("conformance/invalid_cases.json");
  const ids = (invalid.invalid_cases ?? []).map((item) => item.case_id);
  if (ids.length === 0) fail("invalid_case_set_empty");
  if (new Set(ids).size !== ids.length) fail("duplicate_invalid_case_id");

  const requiredErrors = new Set([
    "invalid_relative_path",
    "duplicate_manifest_path",
    "multiple_active_writers",
    "body_not_authorized",
    "fork_detected",
    "instance_id_mismatch",
    "undeclared_memory_gap",
    "authorization_expired",
    "authorization_use_limit_reached"
  ]);
  const presentErrors = new Set((invalid.invalid_cases ?? []).map((item) => item.expected_error));
  for (const requiredError of requiredErrors) {
    if (!presentErrors.has(requiredError)) fail(`missing_invalid_case:${requiredError}`);
  }
}

const packageJson = readJson("package.json");
if (packageJson.private !== true) fail("package_must_remain_private");
if (packageJson.type !== "module") fail("package_must_use_es_modules");

if (failures.length > 0) {
  console.error(`Genesis Ultra validation failed (${failures.length}):`);
  for (const failure of failures) console.error(` - ${failure}`);
  process.exit(1);
}

console.log("Genesis Ultra workspace: OK");
console.log(`Checked ${REQUIRED.length} required artifacts and ${FORBIDDEN.length} forbidden legacy paths.`);
console.log("Workspace hygiene and local Markdown links are consistent.");
console.log("Draft integrity manifest covers every required artifact except its declared self-exclusion.");
console.log("Golden seed and memory hashes match genesis.hash.fields.v0.1.");
console.log("Reminder: passing this tool does not make the draft production-ready.");
