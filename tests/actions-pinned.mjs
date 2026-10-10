import assert from "node:assert/strict";
import { readdir, readFile } from "node:fs/promises";

const workflowsDir = new URL("../.github/workflows/", import.meta.url);
const workflowFiles = (await readdir(workflowsDir)).filter(path => /\.ya?ml$/i.test(path));
assert.ok(workflowFiles.length > 0, "No GitHub Actions workflow files found");

for (const path of workflowFiles) {
  const workflow = await readFile(new URL(path, workflowsDir), "utf8");
  for (const line of workflow.split(/\r?\n/)) {
    const match = line.match(/^\s*-?\s*uses:\s*([^\s#]+)/);
    if (!match) continue;
    assert.match(
      match[1],
      /^[^@]+@[0-9a-f]{40}$/i,
      `${path} uses an action without a full commit SHA: ${match[1]}`
    );
  }
}

console.log("All GitHub Actions references are pinned to full commit SHAs.");
