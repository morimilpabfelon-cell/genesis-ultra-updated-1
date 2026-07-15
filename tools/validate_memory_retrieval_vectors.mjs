#!/usr/bin/env node
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import process from "node:process";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { buildProjection } from "./validate_memory_retrieval.mjs";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const VECTORS = path.join(ROOT, "conformance", "memory_retrieval_vectors.json");
const document = JSON.parse(fs.readFileSync(VECTORS, "utf8"));
const projection = buildProjection(document);
const actual = {
  projection_id: projection.projection_id,
  projection_digest: projection.projection_digest,
  frame_count: projection.frames.length,
  lexicon_count: projection.lexicon.length,
  checkpoint_count: projection.checkpoints.length,
  query_result_digests: projection.query_results.map((item) => item.result_digest)
};
if (JSON.stringify(actual) !== JSON.stringify(document.expected ?? {})) {
  throw new Error("retrieval_expected_vectors_mismatch");
}
const tempPath = path.join(os.tmpdir(), `genesis-retrieval-vectors-${process.pid}.json`);
try {
  fs.writeFileSync(tempPath, JSON.stringify({ ...document, projection }), "utf8");
  const result = spawnSync(process.execPath, [path.join(ROOT, "tools", "validate_memory_retrieval.mjs"), tempPath], {
    cwd: ROOT,
    stdio: "inherit"
  });
  if (result.error) throw result.error;
  process.exitCode = result.status ?? 1;
} finally {
  fs.rmSync(tempPath, { force: true });
}
