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
async function inflateRaw(buf){if(typeof DecompressionStream==="undefined")throw new Error("This browser does not provide ZIP decompression support.");const ds=new DecompressionStream("deflate-raw");const stream=new Blob([buf]).stream().pipeThrough(ds);return new Uint8Array(await new Response(stream).arrayBuffer())}
async function parseZip(file){const buf=await file.arrayBuffer(),a=new Uint8Array(buf);let eocd=-1;for(let i=a.length-22;i>=Math.max(0,a.length-65557);i--){if(u32(a,i)===0x06054b50){eocd=i;break}}if(eocd<0)throw new Error("Not a readable ZIP archive.");const cdSize=u32(a,eocd+12),cdOff=u32(a,eocd+16);const files=new Map();let p=cdOff;while(p<cdOff+cdSize){if(u32(a,p)!==0x02014b50)throw new Error("ZIP central directory is malformed.");const method=u16(a,p+10),comp=u32(a,p+20),uncomp=u32(a,p+24),nl=u16(a,p+28),xl=u16(a,p+30),cl=u16(a,p+32),local=u32(a,p+42);const name=new TextDecoder().decode(a.slice(p+46,p+46+nl));p+=46+nl+xl+cl;if(name.endsWith("/"))continue;const lf=local;if(u32(a,lf)!==0x04034b50)continue;const lnl=u16(a,lf+26),lxl=u16(a,lf+28),start=lf+30+lnl+lxl;const compressed=a.slice(start,start+comp);let data;if(method===0)data=compressed;else if(method===8)data=await inflateRaw(compressed);else{files.set(name,{name,size:uncomp,method,unsupported:true});continue}files.set(name,{name,size:data.length,method,data,sha:await sha256(data)})}return files}
function textOf(entry){if(!entry?.data||entry.data.length>2e6)return null;try{return new TextDecoder("utf-8",{fatal:false}).decode(entry.data)}catch{return null}}
function isText(name){return /\.(txt|md|json|js|mjs|cjs|ts|tsx|jsx|css|html|htm|xml|yml|yaml|env|toml|ini|conf|config|sh|py|rb|go|rs|java|kt|swift)$/i.test(name)}
function scanSecurity(files){const findings=[],secretPatterns=[[/^\s*(AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY|API_KEY|SECRET_KEY|PRIVATE_KEY|PASSWORD|TOKEN)\s*=\s*["']?[^"'\\s]{8,}/im,"Credential-like assignment"],[/\bgh[pousr]_[A-Za-z0-9_]{20,}\b/,"GitHub token-like string"],[/\bsk-[A-Za-z0-9_-]{20,}\b/,"OpenAI-key-like string"],[/-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/,"Private key block"]];for(const [name,e] of files){if(/(^|\/)\.env(\.|$)|(^|\/)(id_rsa|credentials|secrets?)(\.|$)/i.test(name))findings.push({level:"review",file:name,msg:"Sensitive-looking filename"});if(/\.(exe|dll|dylib|so|bin|app)$/i.test(name))findings.push({level:"review",file:name,msg:"Executable/binary file"});if(e.unsupported)findings.push({level:"review",file:name,msg:"Compression method not supported by this browser build"});if(isText(name)){const t=textOf(e);if(t){for(const pat of secretPatterns){const re=pat instanceof RegExp?pat:pat[0];const msg=pat instanceof RegExp?"Secret-like string":pat[1];if(re.test(t)){findings.push({level:"block",file:name,msg});break}}}}}const manifest=files.get("manifest.json")||[...files.values()].find(e=>/\/manifest\.json$/i.test(e.name));if(manifest){try{const m=JSON.parse(textOf(manifest)||"{}");for(const k of ["permissions","host_permissions","optional_permissions"]){if(Array.isArray(m[k])&&m[k].length)findings.push({level:"review",file:manifest.name,msg:`${k}: ${m[k].join(", ")}`})}}catch{findings.push({level:"review",file:manifest.name,msg:"Manifest JSON could not be parsed"})}}return findings}
function packageMeta(files){const p=[...files.values()].find(e=>/^(?:.*\/)?package\.json$/i.test(e.name));if(!p)return null;try{const j=JSON.parse(textOf(p)||"{}");return{name:j.name||"",version:j.version||"",scripts:j.scripts||{},dependencies:Object.keys(j.dependencies||{}),devDependencies:Object.keys(j.devDependencies||{})}}catch{return{error:"package.json could not be parsed"}}}
async function analyze(){$("#status").textContent="Reading both ZIP archives locally…";try{state.oldFiles=await parseZip(state.old);state.newFiles=await parseZip(state.new);const oldSet=new Set(state.oldFiles.keys()),newSet=new Set(state.newFiles.keys());const added=[...newSet].filter(x=>!oldSet.has(x)).sort(),removed=[...oldSet].filter(x=>!newSet.has(x)).sort(),changed=[],same=[];for(const name of [...newSet].filter(x=>oldSet.has(x)).sort()){const a=state.oldFiles.get(name),b=state.newFiles.get(name);if(a.sha&&b.sha&&a.sha!==b.sha)changed.push(name);else if(a.sha&&b.sha)same.push(name)}const sec=[...scanSecurity(state.oldFiles).map(x=>({...x,version:"old"})),...scanSecurity(state.newFiles).map(x=>({...x,version:"new"}))];const oldPkg=packageMeta(state.oldFiles),newPkg=packageMeta(state.newFiles);const findings=[];if(sec.some(x=>x.level==="block"))findings.push({level:"block",msg:"Potential secret/private-key material detected. Review before release."});else if(sec.length)findings.push({level:"review",msg:`${sec.length} security/configuration finding(s) require review.`});else findings.push({level:"pass",msg:"No obvious secret-like patterns or sensitive filenames were detected."});if(newPkg?.version&&/1\.3\.1/.test(newPkg.version)&&/1\.4\.0/.test(state.new.name))findings.push({level:"review",msg:"Archive name suggests 1.4.0 but package.json still reports 1.3.1."});const result={added,removed,changed,same,security:sec,oldPkg,newPkg,findings,oldCount:oldSet.size,newCount:newSet.size};state.result=result;render(result);$("#results").hidden=false;showTab("overview");$("#status").textContent="Analysis complete. Files never left this browser tab."}catch(e){$("#status").textContent="Could not analyze: "+e.message}}
function badge(level){return `<span class="badge ${level}">${level.toUpperCase()}</span>`}
function render(r){$("#summary").innerHTML=`<div class="stats"><div class="stat"><b>${human(r.added.length)}</b><span>Added</span></div><div class="stat"><b>${human(r.removed.length)}</b><span>Removed</span></div><div class="stat"><b>${human(r.changed.length)}</b><span>Changed</span></div><div class="stat"><b>${human(r.same.length)}</b><span>Unchanged</span></div><div class="stat"><b>${human(r.security.length)}</b><span>Security findings</span></div></div>`;$("#tab-overview").innerHTML=`<div class="panel"><h3>Release review</h3>${r.findings.map(f=>`<div class="finding">${badge(f.level)}<div>${esc(f.msg)}</div></div>`).join("")}</div><div class="panel"><h3>Package sizes</h3><div class="finding"><span class="muted">Old</span><b>${esc(state.old.name)}</b><span>${bytes(state.old.size)}</span></div><div class="finding"><span class="muted">New</span><b>${esc(state.new.name)}</b><span>${bytes(state.new.size)}</span></div></div>`;$("#tab-diff").innerHTML=diffHtml(r);$("#tab-security").innerHTML=securityHtml(r);$("#tab-metadata").innerHTML=metaHtml(r);$("#tab-report").innerHTML=reportHtml(r)}
function list(title,arr,cls){return `<div class="panel"><h3>${title} <span class="muted">(${arr.length})</span></h3><div class="filelist">${arr.length?arr.map(x=>`<div class="row ${cls||""}">${esc(x)}</div>`).join(""):'<div class="muted">None</div>'}</div></div>`}
function diffHtml(r){return list("Added files",r.added,"added")+list("Removed files",r.removed,"removed")+list("Changed files",r.changed,"changed")}
function securityHtml(r){return `<div class="panel"><h3>Security/configuration review</h3>${r.security.length?r.security.map(x=>`<div class="finding">${badge(x.level)}<div><b>${esc(x.file)}</b><br>${esc(x.msg)} <span class="muted">(${x.version})</span></div></div>`).join(""):'<div class="finding">'+badge("pass")+'<div>No obvious findings.</div></div>'}</div><div class="panel"><h3>Important limitation</h3><p class="muted">This is a heuristic scanner. A PASS does not prove a project is secure, and a REVIEW finding is not proof that a secret or vulnerability exists.</p></div>`}
function metaHtml(r){return `<div class="panel"><h3>package.json</h3>${r.newPkg?`<p><b>Name:</b> ${esc(r.newPkg.name||"—")}<br><b>Version:</b> ${esc(r.newPkg.version||"—")}<br><b>Dependencies:</b> ${r.newPkg.dependencies?.length||0}<br><b>Dev dependencies:</b> ${r.newPkg.devDependencies?.length||0}</p>`:'<p class="muted">No package.json found.</p>'}</div>`}
function reportHtml(r){const report=makeReport(r);return `<div class="panel"><h3>Release Verification Report</h3><div class="reportActions"><button class="secondary" id="copyReport">Copy report</button><button class="secondary" id="downloadReport">Download report</button></div><pre class="code" id="reportText">${esc(report)}</pre></div>`}
function makeReport(r){return `VERSIONVAULT RELEASE VERIFICATION REPORT
Generated: ${new Date().toISOString()}
Old: ${state.old.name} (${bytes(state.old.size)})
New: ${state.new.name} (${bytes(state.new.size)})

FILE CHANGES
Added: ${r.added.length}
Removed: ${r.removed.length}
Changed: ${r.changed.length}
Unchanged: ${r.same.length}

SECURITY / CONFIGURATION
Findings: ${r.security.length}
${r.security.map(x=>`[${x.level.toUpperCase()}] ${x.version}: ${x.file} — ${x.msg}`).join("\n")||"None detected."}

REVIEW NOTES
${r.findings.map(x=>`[${x.level.toUpperCase()}] ${x.msg}`).join("\n")}

IMPORTANT
SHA-256 values and comparisons describe the files observed during this scan.
They do not prove authorship, authenticity, safety, or absence of vulnerabilities.
`}
document.addEventListener("click",e=>{if(e.target.id==="copyReport"){navigator.clipboard?.writeText(makeReport(state.result));e.target.textContent="Copied";setTimeout(()=>e.target.textContent="Copy report",1200)}if(e.target.id==="downloadReport"){const blob=new Blob([makeReport(state.result)],{type:"text/plain"});const a=document.createElement("a");a.href=URL.createObjectURL(blob);a.download="versionvault-release-report.txt";a.click();URL.revokeObjectURL(a.href)}})
})();