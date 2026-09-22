import { readFile } from "node:fs/promises";
import assert from "node:assert/strict";
import { webcrypto } from "node:crypto";
import vm from "node:vm";

const app = await readFile(new URL("../app.js", import.meta.url), "utf8");
const fixtureB64 = (await readFile(new URL("./fixtures/zip64-fixture.zip.b64", import.meta.url), "utf8")).trim();
const fixture = Buffer.from(fixtureB64, "base64");
const sig = o => fixture.readUInt32LE(o).toString(16);
assert.equal(sig(0), "4034b50");
const findSig = hex => {
  const sig = Buffer.from(hex, "hex");
  return fixture.indexOf(sig);
};
assert.ok(findSig("504b0102") > 0, "ZIP64 fixture central directory signature missing");
assert.ok(findSig("504b0606") > 0, "ZIP64 EOCD signature missing");
assert.ok(findSig("504b0607") > 0, "ZIP64 locator signature missing");
assert.ok(findSig("504b0506") > 0, "ZIP EOCD signature missing");
assert.ok(fixture.length > 100, "ZIP64 fixture unexpectedly small");
assert.match(fixtureB64, /^UEs/);
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

const element=()=>({
  addEventListener(){},
  classList:{toggle(){}},
  textContent:"",
  onclick:null
});
const hooks={};
const context={
  document:{
    querySelector:element,
    querySelectorAll:()=>[],
    addEventListener(){},
    body:{classList:{toggle(){}}}
  },
  TextDecoder,
  Blob,
  Response,
  DecompressionStream,
  Uint8Array,
  crypto:webcrypto,
  console,
  __VERSIONVAULT_TEST_HOOKS__:hooks
};
vm.runInNewContext(app,context,{timeout:1000});
assert.equal(typeof hooks.parseZip,"function","ZIP parser test hook was not installed");
const fileFrom=bytes=>({
  size:bytes.byteLength,
  async arrayBuffer(){return bytes.buffer.slice(bytes.byteOffset,bytes.byteOffset+bytes.byteLength)}
});
const parsed=await hooks.parseZip(fileFrom(fixture));
assert.equal(parsed.size,1,"ZIP64 fixture did not parse to exactly one file");
assert.equal(new TextDecoder().decode(parsed.get("zip64-fixture.txt")?.data),"VersionVault ZIP64 fixture\n");
assert.ok([...parsed.values()].every(entry=>entry.sha&&entry.crc32),"ZIP64 entries were not integrity-checked");

const corrupted=Buffer.from(fixture);
const localNameLength=corrupted.readUInt16LE(26);
const localExtraLength=corrupted.readUInt16LE(28);
const dataStart=30+localNameLength+localExtraLength;
corrupted[dataStart]^=0x01;
await assert.rejects(
  hooks.parseZip(fileFrom(corrupted)),
  /ZIP CRC check failed: zip64-fixture.txt/,
  "ZIP64 CRC rejection did not run"
);

const multiDisk=Buffer.from(fixture);
const eocd=multiDisk.lastIndexOf(Buffer.from("504b0506","hex"));
assert.ok(eocd>0,"ZIP64 fixture EOCD is missing");
multiDisk.writeUInt16LE(1,eocd+4);
await assert.rejects(
  hooks.parseZip(fileFrom(multiDisk)),
  /Multi-disk ZIP archives are not supported/,
  "Multi-disk ZIP rejection did not run"
);

console.log("VersionVault smoke checks passed.");
