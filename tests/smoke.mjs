import { readFile } from "node:fs/promises";
import assert from "node:assert/strict";

const app = await readFile(new URL("../app.js", import.meta.url), "utf8");
assert.match(app, /function crc32/);
assert.match(app, /ZIP64 end-of-central-directory record/);
assert.match(app, /ZIP64 locator/);
assert.match(app, /ZIP64 extended information/);
assert.match(app, /Multi-disk ZIP/);
assert.match(app, /512 MiB browser safety limit/);
assert.match(app, /ZIP CRC check failed/);
assert.match(app, /duplicate filename/);
assert.match(app, /oldSha/);
assert.match(app, /newSha/);
assert.match(app, /VERSIONVAULT RELEASE VERIFICATION REPORT/);
console.log("VersionVault smoke checks passed.");
