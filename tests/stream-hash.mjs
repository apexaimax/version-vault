import assert from "node:assert/strict";
import {readFile} from "node:fs/promises";
import {createHash} from "node:crypto";
import vm from "node:vm";

const source=await readFile(new URL("../stream-hash.js",import.meta.url),"utf8");
const globals={};
vm.runInNewContext(source,{globalThis:globals,Uint8Array,Uint32Array,BigInt});
const {createSha256,createCrc32}=globals.DiffHarborHash;
const digest=bytes=>createHash("sha256").update(bytes).digest("hex");
const crcReference=bytes=>{
  let c=~0;
  for(const b of bytes){c^=b;for(let i=0;i<8;i++)c=(c>>>1)^((c&1)?0xedb88320:0)}
  return (~c)>>>0;
};
assert.equal(createSha256().digest(),"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
assert.equal(createSha256().update(Buffer.from("abc")).digest(),"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
assert.equal(createCrc32().update(Buffer.from("123456789")).digest(),0xcbf43926);
for(const length of [0,1,2,3,55,56,57,63,64,65,119,120,121,1024,65535,1048576]){
  const bytes=Buffer.alloc(length);
  for(let i=0;i<length;i++)bytes[i]=(i*31+17)&255;
  for(const stride of [1,7,31,64,1024,65536]){
    const sha=createSha256(),crc=createCrc32();
    for(let i=0;i<length;i+=stride){const chunk=bytes.subarray(i,i+stride);sha.update(chunk);crc.update(chunk)}
    assert.equal(sha.digest(),digest(bytes),`SHA mismatch: length=${length} stride=${stride}`);
    assert.equal(crc.digest(),crcReference(bytes),`CRC mismatch: length=${length} stride=${stride}`);
  }
}
const finalized=createSha256();finalized.digest();
assert.throws(()=>finalized.update(Buffer.from("x")),/finalized/);
assert.throws(()=>finalized.digest(),/finalized/);
console.log("DiffHarbor incremental hash vectors passed.");
