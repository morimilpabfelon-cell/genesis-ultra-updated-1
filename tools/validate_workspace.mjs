import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const failures = [];

const REQUIRED = JSON.parse(fs.readFileSync(path.join(ROOT, "conformance/required_artifacts.json"), "utf8")).required;

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

for (const relativePath of REQUIRED) {
  if (!fs.existsSync(path.join(ROOT, relativePath))) fail(`missing_required_file:${relativePath}`);
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
console.log(`Checked ${REQUIRED.length} required artifacts.`);
console.log("Golden seed and memory hashes match genesis.hash.fields.v0.1.");
console.log("Reminder: passing this tool does not make the draft production-ready.");
