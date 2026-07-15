#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import { buildProjection, ConformanceError } from "./validate_memory_retrieval.mjs";

function usage(exitCode = 0) {
  console.log(`Genesis deterministic memory retrieval\n\nUsage:\n  node tools/memory_retrieval.mjs build <input.json> [output.json]\n  node tools/memory_retrieval.mjs query <input.json> <text> [--top-k N] [--as-of N] [--anchor event_id]\n\nThe input must contain source_memory_events, accepted_records and optional associative_projection.\nThe tool never writes the append-only chain; it only builds or queries a reconstructible read model.`);
  process.exit(exitCode);
}

function readJson(filePath) {
  return JSON.parse(fs.readFileSync(path.resolve(filePath), "utf8"));
}

function parseOptions(args, latestSequence) {
  const options = { topK: 5, asOf: latestSequence, anchors: [] };
  for (let index = 0; index < args.length; index += 1) {
    const flag = args[index];
    const value = args[index + 1];
    if (flag === "--top-k") {
      options.topK = Number.parseInt(value, 10);
      index += 1;
    } else if (flag === "--as-of") {
      options.asOf = Number.parseInt(value, 10);
      index += 1;
    } else if (flag === "--anchor") {
      options.anchors.push(value);
      index += 1;
    } else {
      throw new Error(`unknown_option:${flag}`);
    }
  }
  return options;
}

const [command, inputPath, ...rest] = process.argv.slice(2);
if (!command || command === "--help" || command === "-h") usage(0);
if (!inputPath) usage(1);

try {
  const document = readJson(inputPath);
  if (command === "build") {
    const projection = buildProjection(document);
    const serialized = `${JSON.stringify(projection, null, 2)}\n`;
    const outputPath = rest[0];
    if (outputPath) {
      fs.writeFileSync(path.resolve(outputPath), serialized, { encoding: "utf8", flag: "wx" });
      console.log(`Retrieval projection written: ${path.resolve(outputPath)}`);
      console.log(`Digest: ${projection.projection_digest}`);
    } else {
      process.stdout.write(serialized);
    }
  } else if (command === "query") {
    const [text, ...optionArgs] = rest;
    if (text === undefined) usage(1);
    const latest = document.source_memory_events?.at(-1)?.sequence;
    if (!Number.isSafeInteger(latest)) throw new Error("source_memory_events_invalid");
    const options = parseOptions(optionArgs, latest);
    const queryDocument = structuredClone(document);
    queryDocument.queries = [{
      query_id: "cli_query",
      text,
      top_k: options.topK,
      as_of_sequence: options.asOf,
      anchor_event_refs: options.anchors
    }];
    delete queryDocument.projection;
    delete queryDocument.must_reject;
    const result = buildProjection(queryDocument).query_results[0];
    process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
  } else {
    usage(1);
  }
} catch (error) {
  const label = error instanceof ConformanceError ? error.message : `memory_retrieval_failed:${error.message}`;
  console.error(label);
  process.exit(1);
}
