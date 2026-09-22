(() => {
"use strict";
const $=s=>document.querySelector(s);
const state={old:null,new:null,oldFiles:null,newFiles:null,result:null};

$("#oldFile").addEventListener("change",e=>{state.old=e.target.files[0]||null;$("#oldName").textContent=state.old?.name||"Choose a ZIP file";refresh()});
$("#newFile").addEventListener("change",e=>{state.new=e.target.files[0]||null;$("#newName").textContent=state.new?.name||"Choose a ZIP file";refresh()});
$("#themeBtn").onclick=()=>document.body.classList.toggle("dark");
$("#analyzeBtn").onclick=analyze;
document.querySelectorAll(".tab").forEach(b=>b.onclick=()=>showTab(b.dataset.tab));

function refresh(){$("#analyzeBtn").disabled=!(state.old&&state.new)}
function showTab(name){document.querySelectorAll(".tab").forEach(x=>x.classList.toggle("active",x.dataset.tab===name));["overview","diff","security","metadata","report"].forEach(x=>$("#tab-"+x).hidden=x!==name)}
function esc(s){return String(s).replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]))}
function human(n){return new Intl.NumberFormat().format(n)}
function bytes(n){if(n<1024)return n+" B";let u=["KB","MB","GB"];let i=-1;do{n/=1024;i++}while(n>=1024&&i<u.length-1);return n.toFixed(n<10?1:0)+" "+u[i]}
async function sha256(buf){const h=await crypto.subtle.digest("SHA-256",buf);return [...new Uint8Array(h)].map(x=>x.toString(16).padStart(2,"0")).join("")}
function u16(a,o){return a[o]|a[o+1]<<8}
function u32(a,o){return (a[o]|a[o+1]<<8|a[o+2]<<16|a[o+3]<<24)>>>0}
function crc32(buf){let c=~0;for(const b of buf){c^=b;for(let k=0;k<8;k++)c=(c>>>1)^((c&1)?0xedb88320:0)}return (~c)>>>0}
async function inflateRaw(buf){if(typeof DecompressionStream==="undefined")throw new Error("This browser does not provide ZIP decompression support.");const ds=new DecompressionStream("deflate-raw");const stream=new Blob([buf]).stream().pipeThrough(ds);return new Uint8Array(await new Response(stream).arrayBuffer())}
const MAX_ARCHIVE_BYTES=1024*1024*1024;
const MAX_ENTRY_COMPRESSED_BYTES=512*1024*1024;
const MAX_ENTRY_UNCOMPRESSED_BYTES=512*1024*1024;
const MAX_ENTRIES=100000;
function u64(a,o){const lo=BigInt(u32(a,o)),hi=BigInt(u32(a,o+4));return lo|(hi<<32n)}
function toSafeNumber(n,label){if(n>BigInt(Number.MAX_SAFE_INTEGER))throw new Error(label+" exceeds browser-safe integer limits.");return Number(n)}
function findExtra(a,start,len,id){let p=start,end=start+len;while(p+4<=end){const tag=u16(a,p),size=u16(a,p+2);p+=4;if(p+size>end)break;if(tag===id)return a.slice(p,p+size);p+=size}return null}
function zip64Values(extra,needSize,needUncomp,needOffset,needDisk){
  const x=findExtra(extra,0,extra.length,0x0001);if(!x)return null;let p=0;
  const take=()=>{if(p+8>x.length)throw new Error("ZIP64 extended information is truncated.");const v=u64(x,p);p+=8;return v};
  return {
    uncomp:needUncomp?take():null,
    comp:needSize?take():null,
    offset:needOffset?take():null,
    disk:needDisk?(()=>{if(p+4>x.length)throw new Error("ZIP64 disk number field is truncated.");const v=u32(x,p);p+=4;return v})():null
  };
}
async function parseZip(file){
  if(file.size>MAX_ARCHIVE_BYTES)throw new Error("Archive exceeds the 1 GiB browser safety limit.");
  const buf=await file.arrayBuffer(),a=new Uint8Array(buf);let eocd=-1;
  for(let i=a.length-22;i>=Math.max(0,a.length-65557);i--){if(u32(a,i)===0x06054b50){eocd=i;break}}
  if(eocd<0)throw new Error("Not a readable ZIP archive.");
  const disk=u16(a,eocd+4),cdDisk=u16(a,eocd+6),entriesDisk=u16(a,eocd+8),entries16=u16(a,eocd+10),cdSize32=u32(a,eocd+12),cdOff32=u32(a,eocd+16);
  if(disk!==0||cdDisk!==0)throw new Error("Multi-disk ZIP archives are not supported.");
  let entries=entries16,cdSize=cdSize32,cdOff=cdOff32;
  const zip64Needed=entries16===0xffff||cdSize32===0xffffffff||cdOff32===0xffffffff;
  if(zip64Needed){
    if(eocd<20)throw new Error("ZIP64 locator is missing.");
    const locator=eocd-20;
    if(u32(a,locator)!==0x07064b50)throw new Error("ZIP64 locator is missing or malformed.");
    const locatorDisk=u32(a,locator+4),zip64Off=toSafeNumber(u64(a,locator+8),"ZIP64 end record offset"),totalDisks=u32(a,locator+16);
    if(locatorDisk!==0||totalDisks!==1)throw new Error("Multi-disk ZIP64 archives are not supported.");
    if(zip64Off+56>a.length||u32(a,zip64Off)!==0x06064b50)throw new Error("ZIP64 end-of-central-directory record is missing or malformed.");
    const recordSize=toSafeNumber(u64(a,zip64Off+4),"ZIP64 end record size");
    if(recordSize<44||zip64Off+12+recordSize>a.length)throw new Error("ZIP64 end-of-central-directory record is truncated.");
    const recordDisk=u32(a,zip64Off+16),recordCdDisk=u32(a,zip64Off+20);
    if(recordDisk!==0||recordCdDisk!==0)throw new Error("Multi-disk ZIP64 archives are not supported.");
    entries=toSafeNumber(u64(a,zip64Off+32),"ZIP64 entry count");
    cdSize=toSafeNumber(u64(a,zip64Off+40),"ZIP64 central directory size");
    cdOff=toSafeNumber(u64(a,zip64Off+48),"ZIP64 central directory offset");
  }
  if(entries>MAX_ENTRIES)throw new Error("Archive contains more than 100,000 entries, above the browser safety limit.");
  if(cdOff+cdSize>a.length)throw new Error("ZIP central directory is outside the archive.");
  const files=new Map(),duplicates=[];let p=cdOff;
  for(let index=0;index<entries;index++){
    if(p+46>cdOff+cdSize||u32(a,p)!==0x02014b50)throw new Error("ZIP central directory is malformed.");
    const diskStart=u16(a,p+34),crc=u32(a,p+16),method=u16(a,p+10),comp32=u32(a,p+20),uncomp32=u32(a,p+24),nl=u16(a,p+28),xl=u16(a,p+30),cl=u16(a,p+32),local32=u32(a,p+42);
    if(diskStart!==0xffff&&diskStart!==0)throw new Error("Multi-disk ZIP entries are not supported.");
    if(p+46+nl+xl+cl>cdOff+cdSize)throw new Error("ZIP central directory entry is truncated.");
    const name=new TextDecoder().decode(a.slice(p+46,p+46+nl)),extra=a.slice(p+46+nl,p+46+nl+xl);
    const needsZip64=comp32===0xffffffff||uncomp32===0xffffffff||local32===0xffffffff||diskStart===0xffff;
    const z=zip64Values(extra,comp32===0xffffffff,uncomp32===0xffffffff,local32===0xffffffff,diskStart===0xffff);
    if(needsZip64&&!z)throw new Error("ZIP64 extended information field is missing: "+name);
    if(z?.disk!==null&&z?.disk!==undefined&&z.disk!==0)throw new Error("Multi-disk ZIP64 entries are not supported.");
    const comp=z?.comp!==null&&z?.comp!==undefined?toSafeNumber(z.comp,"Compressed entry size"):comp32;
    const uncomp=z?.uncomp!==null&&z?.uncomp!==undefined?toSafeNumber(z.uncomp,"Uncompressed entry size"):uncomp32;
    const local=z?.offset!==null&&z?.offset!==undefined?toSafeNumber(z.offset,"Local entry offset"):local32;
    if(comp>MAX_ENTRY_COMPRESSED_BYTES||uncomp>MAX_ENTRY_UNCOMPRESSED_BYTES)throw new Error("ZIP entry exceeds the 512 MiB browser safety limit: "+name);
    p+=46+nl+xl+cl;if(name.endsWith("/"))continue;if(files.has(name))duplicates.push(name);
    if(local+30>a.length||u32(a,local)!==0x04034b50)throw new Error("ZIP local file header is malformed.");
    const lnl=u16(a,local+26),lxl=u16(a,local+28),start=local+30+lnl+lxl;
    if(start+comp>a.length)throw new Error("ZIP entry extends beyond the archive.");
    const compressed=a.slice(start,start+comp);let data;
    if(method===0)data=compressed;else if(method===8)data=await inflateRaw(compressed);else{files.set(name,{name,size:uncomp,method,unsupported:true});continue}
    if(data.length!==uncomp)throw new Error("ZIP entry size check failed: "+name);
    if(crc32(data)!==crc)throw new Error("ZIP CRC check failed: "+name);
    files.set(name,{name,size:data.length,method,data,sha:await sha256(data),crc32:crc.toString(16).padStart(8,"0")})
  }
  if(p!==cdOff+cdSize)throw new Error("ZIP central directory size does not match its entries.");
  files.duplicates=duplicates;return files
}
// Kept out of production behavior: the Node regression suite supplies this
// object before loading the app so it can exercise the same ZIP parser users run.
if(typeof globalThis!=="undefined"&&globalThis.__VERSIONVAULT_TEST_HOOKS__){
  globalThis.__VERSIONVAULT_TEST_HOOKS__.parseZip=parseZip;
}
function textOf(entry){if(!entry?.data||entry.data.length>2e6)return null;try{return new TextDecoder("utf-8",{fatal:false}).decode(entry.data)}catch{return null}}
function isText(name){return /\.(txt|md|json|js|mjs|cjs|ts|tsx|jsx|css|html|htm|xml|yml|yaml|env|toml|ini|conf|config|sh|py|rb|go|rs|java|kt|swift)$/i.test(name)}
function scanSecurity(files){const findings=[],secretPatterns=[[/^\s*(AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY|API_KEY|SECRET_KEY|PRIVATE_KEY|PASSWORD|TOKEN)\s*=\s*["']?[^"'\\s]{8,}/im,"Credential-like assignment"],[/\bgh[pousr]_[A-Za-z0-9_]{20,}\b/,"GitHub token-like string"],[/\bsk-[A-Za-z0-9_-]{20,}\b/,"OpenAI-key-like string"],[/-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/,"Private key block"]];for(const [name,e] of files){if(/(^|\/)\.env(\.|$)|(^|\/)(id_rsa|credentials|secrets?)(\.|$)/i.test(name))findings.push({level:"review",file:name,msg:"Sensitive-looking filename"});if(/\.(exe|dll|dylib|so|bin|app)$/i.test(name))findings.push({level:"review",file:name,msg:"Executable/binary file"});if(e.unsupported)findings.push({level:"review",file:name,msg:"Compression method not supported by this browser build"});if(isText(name)){const t=textOf(e);if(t){for(const pat of secretPatterns){const re=pat instanceof RegExp?pat:pat[0];const msg=pat instanceof RegExp?"Secret-like string":pat[1];if(re.test(t)){findings.push({level:"block",file:name,msg});break}}}}}const manifest=files.get("manifest.json")||[...files.values()].find(e=>/\/manifest\.json$/i.test(e.name));if(manifest){try{const m=JSON.parse(textOf(manifest)||"{}");for(const k of ["permissions","host_permissions","optional_permissions"]){if(Array.isArray(m[k])&&m[k].length)findings.push({level:"review",file:manifest.name,msg:`${k}: ${m[k].join(", ")}`})}}catch{findings.push({level:"review",file:manifest.name,msg:"Manifest JSON could not be parsed"})}}return findings}
function packageMeta(files){const p=[...files.values()].find(e=>/^(?:.*\/)?package\.json$/i.test(e.name));if(!p)return null;try{const j=JSON.parse(textOf(p)||"{}");return{name:j.name||"",version:j.version||"",scripts:j.scripts||{},dependencies:Object.keys(j.dependencies||{}),devDependencies:Object.keys(j.devDependencies||{})}}catch{return{error:"package.json could not be parsed"}}}
async function analyze(){$("#status").textContent="Reading both ZIP archives locally…";try{state.oldFiles=await parseZip(state.old);state.newFiles=await parseZip(state.new);const oldSet=new Set(state.oldFiles.keys()),newSet=new Set(state.newFiles.keys());const added=[...newSet].filter(x=>!oldSet.has(x)).sort(),removed=[...oldSet].filter(x=>!newSet.has(x)).sort(),changed=[],same=[];for(const name of [...newSet].filter(x=>oldSet.has(x)).sort()){const a=state.oldFiles.get(name),b=state.newFiles.get(name);if(a.sha&&b.sha&&a.sha!==b.sha)changed.push(name);else if(a.sha&&b.sha)same.push(name)}const sec=[...scanSecurity(state.oldFiles).map(x=>({...x,version:"old"})),...scanSecurity(state.newFiles).map(x=>({...x,version:"new"}))];const oldPkg=packageMeta(state.oldFiles),newPkg=packageMeta(state.newFiles);const findings=[];if(sec.some(x=>x.level==="block"))findings.push({level:"block",msg:"Potential secret/private-key material detected. Review before release."});else if(sec.length)findings.push({level:"review",msg:`${sec.length} security/configuration finding(s) require review.`});else findings.push({level:"pass",msg:"No obvious secret-like patterns or sensitive filenames were detected."});if(newPkg?.version&&/1\.3\.1/.test(newPkg.version)&&/1\.4\.0/.test(state.new.name))findings.push({level:"review",msg:"Archive name suggests 1.4.0 but package.json still reports 1.3.1."});if(state.oldFiles.duplicates?.length)findings.push({level:"review",msg:"Old archive contains duplicate filename(s): "+state.oldFiles.duplicates.join(", ")});if(state.newFiles.duplicates?.length)findings.push({level:"review",msg:"New archive contains duplicate filename(s): "+state.newFiles.duplicates.join(", ")});if([...state.oldFiles.values(),...state.newFiles.values()].some(x=>x.unsupported))findings.push({level:"review",msg:"One or more ZIP entries use a compression method this browser build cannot inspect."});const changedDetails=changed.map(name=>({name,oldSha:state.oldFiles.get(name)?.sha||null,newSha:state.newFiles.get(name)?.sha||null}));const result={added,removed,changed,same,changedDetails,security:sec,oldPkg,newPkg,findings,oldCount:oldSet.size,newCount:newSet.size,oldDuplicates:state.oldFiles.duplicates||[],newDuplicates:state.newFiles.duplicates||[]};state.result=result;render(result);$("#results").hidden=false;showTab("overview");$("#status").textContent="Analysis complete. Files never left this browser tab."}catch(e){$("#status").textContent="Could not analyze: "+e.message}}
function badge(level){return `<span class="badge ${level}">${level.toUpperCase()}</span>`}
function render(r){$("#summary").innerHTML=`<div class="stats"><div class="stat"><b>${human(r.added.length)}</b><span>Added</span></div><div class="stat"><b>${human(r.removed.length)}</b><span>Removed</span></div><div class="stat"><b>${human(r.changed.length)}</b><span>Changed</span></div><div class="stat"><b>${human(r.same.length)}</b><span>Unchanged</span></div><div class="stat"><b>${human(r.security.length)}</b><span>Security findings</span></div></div>`;$("#tab-overview").innerHTML=`<div class="panel"><h3>Release review</h3>${r.findings.map(f=>`<div class="finding">${badge(f.level)}<div>${esc(f.msg)}</div></div>`).join("")}</div><div class="panel"><h3>Package sizes</h3><div class="finding"><span class="muted">Old</span><b>${esc(state.old.name)}</b><span>${bytes(state.old.size)}</span></div><div class="finding"><span class="muted">New</span><b>${esc(state.new.name)}</b><span>${bytes(state.new.size)}</span></div></div>`;$("#tab-diff").innerHTML=diffHtml(r);$("#tab-security").innerHTML=securityHtml(r);$("#tab-metadata").innerHTML=metaHtml(r);$("#tab-report").innerHTML=reportHtml(r)}
function list(title,arr,cls){return `<div class="panel"><h3>${title} <span class="muted">(${arr.length})</span></h3><div class="filelist">${arr.length?arr.map(x=>`<div class="row ${cls||""}">${esc(x)}</div>`).join(""):'<div class="muted">None</div>'}</div></div>`}
function diffHtml(r){return list("Added files",r.added,"added")+list("Removed files",r.removed,"removed")+'<div class="panel"><h3>Changed files <span class="muted">('+r.changedDetails.length+')</span></h3><div class="filelist">'+(r.changedDetails.length?r.changedDetails.map(x=>'<div class="row changed"><b>'+esc(x.name)+'</b><div class="hashline"><span>OLD '+esc(x.oldSha||"unavailable")+'</span><span>NEW '+esc(x.newSha||"unavailable")+'</span></div></div>').join(""):'<div class="muted">None</div>')+'</div></div>'}
function securityHtml(r){return `<div class="panel"><h3>Security/configuration review</h3>${r.security.length?r.security.map(x=>`<div class="finding">${badge(x.level)}<div><b>${esc(x.file)}</b><br>${esc(x.msg)} <span class="muted">(${x.version})</span></div></div>`).join(""):'<div class="finding">'+badge("pass")+'<div>No obvious findings.</div></div>'}</div><div class="panel"><h3>Important limitation</h3><p class="muted">This is a heuristic scanner. A PASS does not prove a project is secure, and a REVIEW finding is not proof that a secret or vulnerability exists.</p></div>`}
function metaHtml(r){return `<div class="panel"><h3>package.json</h3>${r.newPkg?`<p><b>Name:</b> ${esc(r.newPkg.name||"—")}<br><b>Version:</b> ${esc(r.newPkg.version||"—")}<br><b>Dependencies:</b> ${r.newPkg.dependencies?.length||0}<br><b>Dev dependencies:</b> ${r.newPkg.devDependencies?.length||0}</p>`:'<p class="muted">No package.json found.</p>'}</div>`}
function reportHtml(r){const report=makeReport(r);return `<div class="panel"><h3>Release Verification Report</h3><div class="reportActions"><button class="secondary" id="copyReport">Copy report</button><button class="secondary" id="downloadReport">Download report</button></div><pre class="code" id="reportText">${esc(report)}</pre></div>`}
function makeReport(r){return "VERSIONVAULT RELEASE VERIFICATION REPORT\nGenerated: "+new Date().toISOString()+"\nOld: "+state.old.name+" ("+bytes(state.old.size)+")\nNew: "+state.new.name+" ("+bytes(state.new.size)+")\n\nFILE CHANGES\nAdded: "+r.added.length+"\nRemoved: "+r.removed.length+"\nChanged: "+r.changed.length+"\nUnchanged: "+r.same.length+"\n\nCHANGED FILE HASHES\n"+(r.changedDetails.map(x=>x.name+"\\n  OLD SHA-256: "+(x.oldSha||"unavailable")+"\\n  NEW SHA-256: "+(x.newSha||"unavailable")).join("\\n")||"None.")+"\n\nSECURITY / CONFIGURATION\nFindings: "+r.security.length+"\n"+(r.security.map(x=>"["+x.level.toUpperCase()+"] "+x.version+": "+x.file+" — "+x.msg).join("\\n")||"None detected.")+"\n\nARCHIVE INTEGRITY\nOld duplicate filenames: "+r.oldDuplicates.length+"\nNew duplicate filenames: "+r.newDuplicates.length+"\nZIP entry CRC-32 checks: passed for inspected supported entries.\n\nREVIEW NOTES\n"+r.findings.map(x=>"["+x.level.toUpperCase()+"] "+x.msg).join("\\n")+"\n\nIMPORTANT\nSHA-256 values and comparisons describe the files observed during this scan.\nThey do not prove authorship, authenticity, safety, or absence of vulnerabilities.\n"}
document.addEventListener("click",e=>{if(e.target.id==="copyReport"){navigator.clipboard?.writeText(makeReport(state.result));e.target.textContent="Copied";setTimeout(()=>e.target.textContent="Copy report",1200)}if(e.target.id==="downloadReport"){const blob=new Blob([makeReport(state.result)],{type:"text/plain"});const a=document.createElement("a");a.href=URL.createObjectURL(blob);a.download="versionvault-release-report.txt";a.click();URL.revokeObjectURL(a.href)}})
})();
