import { readFile } from "node:fs/promises";
import assert from "node:assert/strict";
import { webcrypto } from "node:crypto";
import { deflateRawSync } from "node:zlib";
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
assert.equal(typeof hooks.inflateRaw,"function","bounded ZIP inflater test hook was not installed");
const fileFrom=bytes=>({
  size:bytes.byteLength,
  async arrayBuffer(){return bytes.buffer.slice(bytes.byteOffset,bytes.byteOffset+bytes.byteLength)},
  slice(start=0,end=bytes.byteLength){const part=bytes.subarray(start,end);return {async arrayBuffer(){return part.buffer.slice(part.byteOffset,part.byteOffset+part.byteLength)}}}
});
const parsed=await hooks.parseZip(fileFrom(fixture));
assert.equal(parsed.size,1,"ZIP64 fixture did not parse to exactly one file");
assert.equal(new TextDecoder().decode(parsed.get("zip64-fixture.txt")?.data),"VersionVault ZIP64 fixture\n");
assert.ok([...parsed.values()].every(entry=>entry.sha&&entry.crc32),"ZIP64 entries were not integrity-checked");

// Regression: central-directory and local-header filenames must agree.
const mismatchedName=Buffer.from(fixture);
const localNameLengthForMismatch=mismatchedName.readUInt16LE(26);
assert.ok(localNameLengthForMismatch>0,"Fixture needs a local filename");
mismatchedName[30]^=0x01;
await assert.rejects(
  hooks.parseZip(fileFrom(mismatchedName)),
  /ZIP local filename mismatch/i,
  "Conflicting ZIP filenames must be rejected"
);

// Regression: local compression method must match the central directory.
const mismatchedMethod=Buffer.from(fixture);
mismatchedMethod.writeUInt16LE(8,8); // Local header claims DEFLATE; central entry is STORED.
await assert.rejects(
  hooks.parseZip(fileFrom(mismatchedMethod)),
  /ZIP local compression method mismatch/i,
  "Conflicting ZIP compression methods must be rejected"
);

// Malformed ZIP64 locator must never be interpreted as a valid archive.
const invalidZip64Locator=Buffer.from(fixture);
const zip64LocatorAt=invalidZip64Locator.lastIndexOf(Buffer.from("504b0607","hex"));
assert.ok(zip64LocatorAt>0,"ZIP64 locator is missing");
invalidZip64Locator.writeBigUInt64LE(BigInt(invalidZip64Locator.length+4096),zip64LocatorAt+8);
await assert.rejects(
  hooks.parseZip(fileFrom(invalidZip64Locator)),
  /ZIP64|outside|bounds|malformed|truncated/i,
  "Out-of-bounds ZIP64 end-of-central-directory offsets must be rejected"
);

// Malformed ZIP64 record: reject a declared size larger than available bytes.
const truncatedZip64Record=Buffer.from(fixture);
const zip64RecordAt=truncatedZip64Record.lastIndexOf(Buffer.from("504b0606","hex"));
assert.ok(zip64RecordAt>0,"ZIP64 EOCD record is missing");
truncatedZip64Record.writeBigUInt64LE(BigInt(truncatedZip64Record.length+4096),zip64RecordAt+4);
await assert.rejects(
  hooks.parseZip(fileFrom(truncatedZip64Record)),
  /ZIP64|outside|bounds|malformed|truncated|record/i,
  "Oversized ZIP64 end-of-central-directory records must be rejected"
);

// Memory boundary: oversized archives must be rejected before arrayBuffer is called.
let oversizedArchiveRead=false;
await assert.rejects(
  hooks.parseZip({
    size:1024*1024*1024+1,
    async arrayBuffer(){oversizedArchiveRead=true;throw new Error("oversized archive was read")}
  }),
  /Archive exceeds the 1 GiB browser safety limit/,
  "Oversized archives must be rejected at the file-size boundary"
);
assert.equal(oversizedArchiveRead,false,"Oversized ZIP was loaded into memory");

// Batch memory regressions: compressed output and metadata limits.
const expandedPayload2=Buffer.alloc(1024*1024,65);
await assert.rejects(
  hooks.inflateRaw(deflateRawSync(expandedPayload2),4096),
  /exceeded.*limit|beyond.*limit/i,
  "Highly compressible content must respect the decompression output limit"
);
const inflatedWithinLimit=await hooks.inflateRaw(deflateRawSync(Buffer.from("bounded payload")),1024);
assert.equal(new TextDecoder().decode(inflatedWithinLimit),"bounded payload");

// Reject an excessive declared entry count before processing central entries.
const excessiveEntryCount=Buffer.from(fixture);
const eocdForCount=excessiveEntryCount.lastIndexOf(Buffer.from("504b0506","hex"));
const zip64ForCount=excessiveEntryCount.lastIndexOf(Buffer.from("504b0606","hex"));
assert.ok(eocdForCount>0&&zip64ForCount>0);
excessiveEntryCount.writeBigUInt64LE(100001n,zip64ForCount+32);
await assert.rejects(
  hooks.parseZip(fileFrom(excessiveEntryCount)),
  /more than 100,000 entries/i,
  "Excessive ZIP64 entry count must be rejected"
);

// Red test for bounded ZIP reads: parser must not load the entire archive.
let fullArchiveReads=0;
const sliceReads=[];
const slicedFixture={
  size:fixture.byteLength,
  async arrayBuffer(){fullArchiveReads++;throw new Error("whole-archive read forbidden")},
  slice(start=0,end=fixture.byteLength){
    sliceReads.push([start,end]);
    const part=fixture.subarray(start,end);
    return {async arrayBuffer(){return part.buffer.slice(part.byteOffset,part.byteOffset+part.byteLength)}};
  }
};
const slicedParsed=await hooks.parseZip(slicedFixture);
assert.equal(new TextDecoder().decode(slicedParsed.get("zip64-fixture.txt")?.data),"VersionVault ZIP64 fixture\\n");
assert.equal(fullArchiveReads,0,"ZIP parser must use bounded Blob slices instead of file.arrayBuffer()");
assert.ok(sliceReads.length>=2,"ZIP parser should read metadata and entry data in bounded ranges");

const expandedPayload=Buffer.alloc(1024*1024,65);
await assert.rejects(
  hooks.inflateRaw(deflateRawSync(expandedPayload),1024),
  /exceeded.*limit|beyond.*limit/i,
  "Inflater must stop when output exceeds its caller-provided bound"
);

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
