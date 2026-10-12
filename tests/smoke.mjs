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


// Analysis cleanup must release both archive maps and invalidate stale results.
assert.match(app,/finally\{state\.oldFiles=null;state\.newFiles=null\}/);
assert.match(app,/state\.result=null;try\{state\.oldFiles=await parseZip/);
assert.match(app,/catch\(e\)\{state\.result=null;\$\("#results"\)\.hidden=true/);
// Bounded archive reads must not regress to reading the complete File.
assert.doesNotMatch(app,/file\.arrayBuffer\(\)/);

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
assert.equal(new TextDecoder().decode(slicedParsed.get("zip64-fixture.txt")?.data),"VersionVault ZIP64 fixture\n");
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


// Stress and boundary checks: large logical archive, bounded reads, and repeated scans.
const logicalSize=64*1024*1024;
let largestRead=0,readCount=0;
const sparseArchive={
  size:logicalSize,
  slice(start,end){
    const length=end-start;
    largestRead=Math.max(largestRead,length);readCount++;
    // Sparse prefix is zero-filled; valid fixture is placed at the end.
    const out=Buffer.alloc(length);
    const fixtureStart=logicalSize-fixture.length;
    const overlapStart=Math.max(start,fixtureStart),overlapEnd=Math.min(end,logicalSize);
    if(overlapEnd>overlapStart)fixture.copy(out,overlapStart-start,overlapStart-fixtureStart,overlapEnd-fixtureStart);
    return {async arrayBuffer(){return out.buffer.slice(out.byteOffset,out.byteOffset+out.byteLength)}};
  }
};
await assert.rejects(hooks.parseZip(sparseArchive),/ZIP64|malformed|missing|outside|central directory|local file header/i,
  "Sparse archive with relocated ZIP64 offsets must be rejected safely");
assert.ok(largestRead<=65557,"Sparse archive metadata reads must stay bounded");
assert.ok(readCount>=1,"Sparse archive must be inspected");

for(let i=0;i<20;i++){
  const again=await hooks.parseZip(fileFrom(fixture));
  assert.equal(again.get("zip64-fixture.txt")?.sha,parsed.get("zip64-fixture.txt")?.sha,
    "Repeated comparisons must produce stable hashes");
  assert.equal(again.get("zip64-fixture.txt")?.crc32,parsed.get("zip64-fixture.txt")?.crc32,
    "Repeated comparisons must preserve CRC checks");
}
for(const limit of [0,1,32,1024,65536]){
  await assert.rejects(hooks.inflateRaw(deflateRawSync(Buffer.alloc(256*1024,88)),limit),
    /beyond.*limit/i,"Inflation must reject output above "+limit+" bytes");
}


// Additional adversarial regression matrix: malformed signatures and truncated archives.
for(const cut of [0,1,4,16,21,22,32,64]){
  const truncated=fixture.subarray(0,Math.min(cut,fixture.length));
  await assert.rejects(hooks.parseZip(fileFrom(truncated)),
    /ZIP|readable|bounds|malformed|truncated|missing|outside/i,
    "Truncated ZIP prefix of "+cut+" bytes must fail safely");
}
for(const mutate of [
  bytes=>bytes.fill(0,0,4),
  bytes=>bytes.fill(0,bytes.length-22,bytes.length),
  bytes=>bytes.writeUInt16LE(1,bytes.lastIndexOf(Buffer.from("504b0506","hex"))+6),
  bytes=>bytes.writeUInt32LE(0xffffffff,bytes.lastIndexOf(Buffer.from("504b0607","hex"))+4)
]){
  const malformed=Buffer.from(fixture);mutate(malformed);
  await assert.rejects(hooks.parseZip(fileFrom(malformed)),
    /ZIP|Multi-disk|malformed|missing|outside|readable/i,
    "Mutated ZIP structural fields must be rejected");
}


// Binary entries must remain hashable without retaining their decompressed payload.
const binaryFixture=Buffer.from(fixture);
const oldName=Buffer.from("zip64-fixture.txt"),newName=Buffer.from("zip64-fixture.bin");
let replaced=0;
for(let at=0;(at=binaryFixture.indexOf(oldName,at))>=0;at+=newName.length){
  newName.copy(binaryFixture,at);replaced++;
}
assert.equal(replaced,2,"ZIP64 fixture must have local and central filenames");
const binaryParsed=await hooks.parseZip(fileFrom(binaryFixture));
const binaryEntry=binaryParsed.get("zip64-fixture.bin");
assert.ok(binaryEntry?.sha&&binaryEntry?.crc32,"Binary entries must retain integrity metadata");
assert.equal(binaryEntry.data,undefined,"Binary entries must not retain payload buffers");
assert.equal(binaryEntry.sha,parsed.get("zip64-fixture.txt").sha,"Binary and text names must hash the same bytes");

console.log("VersionVault smoke checks passed.");
