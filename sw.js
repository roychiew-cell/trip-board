// Only a successfully decrypted payload is an offline copy. Incoming payloads remain candidates.
// Activation never waits for picture downloads; clients request bounded, resumable preparation afterwards.
const SHELL = 'tb-shell-dec454d6e6e2', DATA = 'tb-data';
const GOOD = 'payload-good.json', LIST = 'precache.json', PENDING = 'payload-pending.json', RESERVE = 'payload-reserve.bin', ETAG = 'payload-etag.json';
const SHELL_FILES = ['index.html', 'manifest.webmanifest', 'icon-192.png', 'icon-512.png', 'icon-maskable-512.png', 'apple-touch-icon.png'];
// P6 (F2): LIVE_WAIT_MS bounds the wait for response HEADERS only. Bodies have their own limits: 30 s for a picture or
// a shell file; for the encrypted copy PAYLOAD_BODY_MS while a saved copy exists (the lock screen gets the saved copy
// after LIVE_WAIT_MS and the download carries on in the background), and no limit while nothing is saved yet.
// P6 (F8): at most LAZY_QUEUE gallery saves wait for the write lock; older queued ones are dropped (the picture was shown).
// P7 (C4): shell files and precache.json get one TOTAL deadline of LIVE_WAIT_MS (headers and body together). While a picture
// retry runs, the worker says so every OPTIONAL_BEAT_MS, because one picture may take up to ASSET_WAIT_MS for its headers plus
// ASSET_WAIT_MS for its body (about a minute) and the footer's picture watchdog waits only 45 s without a sign of life.
const LIVE_WAIT_MS = 8000, ASSET_WAIT_MS = 30000, PAYLOAD_BODY_MS = 270000, PARALLEL = 6, MAX_LAZY = 48, LAZY_QUEUE = 8, OPTIONAL_BEAT_MS = 15000;
const scope = self.registration.scope;

function assetList(raw, payload) {
  // A flat array has no provenance. Keep the good payload, but require a rebuild before certifying its assets.
  if (!raw || Array.isArray(raw) || raw.generation !== generationOf(payload) || !Array.isArray(raw.essential) || !Array.isArray(raw.lazy)) return null;
  const safe = (u) => typeof u === 'string' && /^(?:img\/|vendor\/|index\.html$|manifest\.webmanifest$|(?:icon-[\w-]+|apple-touch-icon)\.png$)/.test(u) && !u.includes('..') && !/[?%#\\]/.test(u);
  if (![...raw.essential, ...raw.lazy].every(safe)) return null;
  const essential = [...new Set([...SHELL_FILES, ...raw.essential])], integrity = raw.integrity || {};
  if (Object.values(integrity).some((v) => typeof v !== 'string' || !/^[a-f0-9]{64}$/.test(v))) return null;
  // Reject legacy/incomplete objects as well as arrays: every essential, including injected shell files, needs a digest.
  if (essential.some((u) => !Object.hasOwn(integrity, u) || !/^[a-f0-9]{64}$/.test(integrity[u]))) return null;
  return { generation: raw.generation, essential, lazy: [...new Set(raw.lazy)].filter((u) => !essential.includes(u)), integrity };
}
function offlinePlan(payload, raw, verified) {
  const list = payload && assetList(raw, payload);
  if (!list) return { ready: false, missing: [], prune: [], saved: 0, total: 0 };
  const have = new Set(verified), keep = new Set([...list.essential, ...list.lazy]);
  const missing = list.essential.filter((u) => !have.has(u));
  return { ready: have.has(GOOD) && have.has(LIST) && !missing.length, missing,
    prune: verified.filter((u) => /^(img|vendor)\//.test(u) && !keep.has(u)), saved: list.essential.length - missing.length, total: list.essential.length };
}
// One initial pass and two retries, never an overlapping pass or an unbounded loop.
function retryDecision(round, missing, online, open) {
  if (!missing) return { action: 'done', delay: 0 };
  if (!online || !open) return { action: 'paused', delay: 0 };
  return round < 3 ? { action: 'retry', delay: round * 1000 } : { action: 'failed', delay: 0 };
}
function validPayload(p) {
  try {
    return !!p && p.v === 1 && !!p.kdf && Number.isInteger(p.kdf.iter) && p.kdf.iter >= 100000 && p.kdf.iter <= 5000000 &&
      typeof p.kdf.salt === 'string' && atob(p.kdf.salt).length >= 16 && !!p.enc && typeof p.enc.iv === 'string' && atob(p.enc.iv).length === 12 &&
      typeof p.ct === 'string' && p.ct.length > 32 && atob(p.ct).length > 16 && typeof p.kid === 'string' && typeof p.built === 'string';
  } catch (_) { return false; }
}
async function checkedPayload(response) {
  if (!response.ok || response.redirected) return null;
  try {
    const p = await response.clone().json();
    if (!validPayload(p)) return null;
    const salt = Uint8Array.from(atob(p.kdf.salt), (c) => c.charCodeAt(0)), iter = new TextEncoder().encode(String(p.kdf.iter));
    const bytes = new Uint8Array(salt.length + iter.length); bytes.set(salt); bytes.set(iter, salt.length);
    const hash = new Uint8Array(await crypto.subtle.digest('SHA-256', bytes));
    return [...hash].map((b) => b.toString(16).padStart(2, '0')).join('').slice(0, 16) === p.kid ? p : null;
  } catch (_) { return null; }
}
const generationOf = (p) => p && (p.generation || p.built);
const relative = (request) => new URL(typeof request === 'string' ? request : request.url, scope).href.slice(scope.length).split(/[?#]/)[0];
const json = (p, headers = {}) => new Response(JSON.stringify(p), { headers: { 'Content-Type': 'application/json', ...headers } });
async function readJson(cache, key) { try { const r = await cache.match(key); return r ? await r.json() : null; } catch (_) { return null; } }
async function digest(bytes) { return [...new Uint8Array(await crypto.subtle.digest('SHA-256', bytes))].map((b) => b.toString(16).padStart(2, '0')).join(''); }
const fingerprint = (p) => digest(new TextEncoder().encode(JSON.stringify(p)));
// P6 (F8): the saved record is immutable per bundle key, so its fingerprint and size are computed once per worker.
const savedFingerprints = new WeakMap(), recordSizes = new WeakMap();
function savedFingerprint(p) { if (!savedFingerprints.has(p)) savedFingerprints.set(p, fingerprint(p)); return savedFingerprints.get(p); }
function recordBytes(record) { if (!recordSizes.has(record)) recordSizes.set(record, new TextEncoder().encode(JSON.stringify(record)).length); return recordSizes.get(record); }
let mutations = Promise.resolve();
function mutate(work) {
  const next=mutations.then(()=>self.navigator&&self.navigator.locks?self.navigator.locks.request('trip-board-cache:'+scope,work):work());
  mutations=next.catch(()=>{});return next;
}
async function broadcast(message) {
  for (const c of await self.clients.matchAll({ includeUncontrolled: true })) try { if (!c.url || c.url.startsWith(scope)) c.postMessage(message); } catch (_) { /* closed tab */ }
}
const notify = async (generation, plan, state, extra = {}) => {
  // P7 (C1): a saved copy that answers for its own generation also says whether a newer build is already downloaded, so a
  // footer that did not exist when the download finished (the lock screen was still showing) still learns about it.
  if(state==='ready'&&extra.downloaded===undefined)Object.assign(extra,await stagedNote(await caches.open(DATA),generation)||{});
  if(extra.failure==='storage'&&!plan.payloadBytes){const r=await targetRecord(await caches.open(DATA),generation);if(r)extra.payloadBytes=new TextEncoder().encode(JSON.stringify(r.payload)).length}
  if(extra.failure==='storage')Object.assign(extra,await storageNeed(generation,plan,extra));
  return broadcast({type:'offline-status',generation,...plan,state,...extra});
};
// P6 (F12): a storage failure states how much more space is needed when the browser gives an estimate.
async function storageNeed(generation,plan,extra){
  try{
    const r=await targetRecord(await caches.open(DATA),generation),sizes=(r&&r.manifest&&r.manifest.sizes)||{};
    let need=(plan.payloadBytes||extra.payloadBytes||0)+2048;for(const u of plan.missing||[])need+=Number(sizes[u])||0;
    const est=self.navigator&&self.navigator.storage&&self.navigator.storage.estimate?await self.navigator.storage.estimate():null;
    const free=est&&Number.isFinite(est.quota)&&Number.isFinite(est.usage)?est.quota-est.usage:null;
    return free===null?{needBytes:need}:{needBytes:need,shortfallBytes:Math.max(0,need-free)};
  }catch(_){return {}}
}

self.addEventListener('install', (event) => event.waitUntil((async () => {
  const existed = (await caches.keys()).includes(SHELL);
  try {
    try { await (await caches.open(SHELL)).addAll(['./', ...SHELL_FILES]); }
    catch (_) {
      if (!(self.navigator&&self.navigator.locks) && await goodRecord(await caches.open(DATA))) throw new Error('Close the app and free storage before updating');
      // addAll may have partially written before quota rejection. Retry small shell files with the same budget recovery.
      if (!existed) await caches.delete(SHELL);
      const data = await caches.open(DATA), target = await caches.open(SHELL);
      for (const url of ['./', ...SHELL_FILES]) {
        const r = await fetchBounded(url, LIVE_WAIT_MS); if (!r.ok) throw new Error('shell unavailable');
        await mutate(() => putWithBudget(data, url, r, null, false, target, false));
      }
    }
    // Without cross-worker locks, normal waiting activation keeps old/new writers from overlapping.
    if ((self.navigator&&self.navigator.locks)||!await goodRecord(await caches.open(DATA))) await self.skipWaiting();
  } catch (error) { if (!existed) await caches.delete(SHELL); if(self.navigator?.locks)await mutate(async()=>{const data=await caches.open(DATA);await reservePayload(data,await goodRecord(data))});throw error; } // old worker/shell remain usable
})()));
// P6 (F12): a shell install may spend the reserve (quota recovery); the new worker rebuilds it under the lock at once,
// and prunes old shells when the saved copy already uses this shell.
self.addEventListener('activate', (event) => event.waitUntil((async () => {
  await self.clients.claim();
  try { await mutate(async () => { const data = await caches.open(DATA), record = await goodRecord(data); if (!record) return; await reservePayload(data, record); await pruneShells(await currentList(data)); }); } catch (_) { /* best effort */ }
})()));
// P6 (F2): headerMs bounds the wait for the response headers; bodyMs (0 = no limit) bounds the body separately, so a
// slow but working connection still completes a download.
async function fetchHead(request, headerMs, bodyMs, headers) {
  const controller = new AbortController(); let timer = setTimeout(() => controller.abort(), headerMs), r;
  try { r = await fetch(request, headers ? { cache: 'no-store', signal: controller.signal, headers } : { cache: 'no-store', signal: controller.signal }); } finally { clearTimeout(timer); }
  if (r.redirected) { controller.abort(); throw new Error('redirected response'); }
  timer = bodyMs > 0 ? setTimeout(() => controller.abort(), bodyMs) : null;
  const body = r.arrayBuffer().then((b) => new Response(b, { status: r.status, statusText: r.statusText, headers: r.headers }))
    .finally(() => { if (timer !== null) clearTimeout(timer); });
  return { ok: r.ok, status: r.status, etag: r.headers.get('ETag'), body };
}
async function fetchBounded(request, ms, bodyMs = ASSET_WAIT_MS) { return (await fetchHead(request, ms, bodyMs)).body; }
// P7 (C4): one deadline for the whole answer (headers and body). P6 bounded them separately, so a small file such as the shell
// or precache.json could wait 8 s for headers and then up to 30 s more for its body before the saved copy was used.
async function fetchTotal(request, ms) {
  const controller = new AbortController(), timer = setTimeout(() => controller.abort(), ms);
  try {
    const r = await fetch(request, { cache: 'no-store', signal: controller.signal });
    if (r.redirected) { controller.abort(); throw new Error('redirected response'); }
    const bytes = await r.arrayBuffer();
    return new Response(bytes, { status: r.status, statusText: r.statusText, headers: r.headers });
  } finally { clearTimeout(timer); }
}
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
// GOOD is a small atomic pointer to an immutable bundle. A disposable reserve covers
// another payload plus pointer/headroom, because Chrome charges old AND new bytes during replacement.
async function reserveFull(data){const record=await goodRecord(data);if(!record)return false;const r=await data.match(RESERVE);return !!r&&(Number(r.headers.get('X-TB-Reserve-Bytes'))||0)>=recordBytes(record)+2048}
async function reservePayload(data, record) {
  if(!record)return false;
  const minimum=recordBytes(record)+2048,desired=minimum+14336;
  const old=await data.match(RESERVE),size=old?Number(old.headers.get('X-TB-Reserve-Bytes'))||(await old.arrayBuffer()).byteLength:0;
  if(size>=minimum)return true;
  // P6 (F12): delete a smaller reserve first (replacing it in place would need old plus new bytes at once); its own
  // size stays one of the tiers, so a failed larger write never leaves less than before.
  if(old)await data.delete(RESERVE);
  // Best effort, including useful smaller reservations on small quotas. Never evict an essential for a reserve.
  for(const bytes of [...new Set([desired,minimum,Math.min(minimum,16384),size,1024])].filter(b=>b>0).sort((a,b)=>b-a)){
    try{await data.put(RESERVE,new Response(new Uint8Array(bytes),{headers:{'X-TB-Reserve-Bytes':String(bytes),'X-TB-Reserve-Full':String(bytes>=minimum)}}));return bytes>=minimum}catch(_){}
  }
  return false;
}
async function cleanBundles(data,except) {
  const pointer=await readJson(data,GOOD);
  for(const r of await data.keys())if(relative(r).startsWith('bundle-')&&relative(r)!==pointer?.bundle&&relative(r)!==except)await data.delete(r);
}
async function writeGood(data,record) {
  const body=JSON.stringify(record),key='bundle-'+await digest(new TextEncoder().encode(body))+'.json';
  await cleanBundles(data,key);
  await data.delete(PENDING); await removeCandidates(data);
  try{
    // P6 (F24): until the pointer switches, the OLD copy is still the saved one. Quota recovery for these two writes may
    // drop candidates, the journal, orphan bundles, the reserve and expendable gallery pictures, but never prunes
    // (pruneObsolete against the NEW list would delete the old copy's optional pictures before the switch).
    if(!await data.match(key))await putWithBudget(data,key,json(record),assetList(record.manifest,record.payload),false,data,false,key);
    // Only a tiny pointer is replaced. Recovery protects this in-flight bundle as well as GOOD.
    await putWithBudget(data,GOOD,json({bundle:key,generation:generationOf(record.payload)}),assetList(record.manifest,record.payload),false,data,false,key);
    await cleanBundles(data);
  }catch(error){await cleanBundles(data);await reservePayload(data,await goodRecord(data));throw error}
}
// Legacy P2/P3 good entries remain readable until the first successful pointer switch.
let goodMemo = null;
async function goodRecord(data) {
  const r = await readJson(data, GOOD);
  if (!r) return null;
  if (r.bundle) {
    // Fetch readers do not hold the write lock. A commit can remove the bundle
    // after we read its pointer; retry the authoritative pointer in that case.
    // P6 (F8): bundles are immutable (named by their digest), so the parsed record is kept per bundle key.
    let pointer=r;
    for(let i=0;i<4;i++){
      if(goodMemo&&goodMemo.bundle===pointer.bundle&&await data.match(pointer.bundle))return goodMemo.record;
      const record=await readJson(data,pointer.bundle);if(record){goodMemo={bundle:pointer.bundle,record};return record}
      pointer=await readJson(data,GOOD);if(!pointer?.bundle)return null}
    return null;
  }
  if (r.payload) return r;
  const old = await data.match(GOOD);
  return {payload:r, manifest:await readJson(data, LIST), retired:JSON.parse(old.headers.get('X-TB-Retired') || '[]')};
}
async function currentList(data) { const r = await goodRecord(data); return r && assetList(r.manifest, r.payload); }
let pending = null;
async function pendingRecord(data) {
  const r=pending||await readJson(data,PENDING);if(!r)return null;
  const good=await goodRecord(data), current=good&&await savedFingerprint(good.payload);
  if(good&&(good.payload.built>r.payload.built||(good.retired||[]).includes(generationOf(r.payload))||current===r.verified||(r.baseGood&&r.baseGood!==current&&good.payload.built>=r.payload.built))){pending=null;return null}
  if(r.verified!==await fingerprint(r.payload))return null;
  if(pending||assetList(r.manifest,r.payload)){pending=r;return r}return null;
}
const assetKey = (hash) => 'asset-' + hash + '.bin';
async function targetRecord(data, generation) {
  const good = await goodRecord(data);
  if (good && generationOf(good.payload) === generation) return good;
  const next = await pendingRecord(data);
  return next && generationOf(next.payload) === generation ? next : null;
}
async function protectedAssets(data, extra) {
  const records = [await goodRecord(data), await pendingRecord(data)];
  const paths = new Set(), hashes = new Set(), references=new Map(), conservative=new Set();let allImmutable=false;
  for (const r of records) {
    const list = r && assetList(r.manifest,r.payload);
    if(!list){
      if(r){allImmutable=true;for(const u of (Array.isArray(r.manifest)?r.manifest:r.manifest?.essential||[]))if(typeof u==='string'&&/^(img|vendor)\//.test(u)&&!u.includes('..')&&!/[?%#\\]/.test(u)){paths.add(u);conservative.add(u)}}
      continue;
    }
    for(const h of Object.values(r.gallery||{}))hashes.add(assetKey(h));
    for (const u of list.essential) { paths.add(u); hashes.add(assetKey(list.integrity[u]));if(!references.has(u))references.set(u,new Set());references.get(u).add(list.integrity[u]); }
  }
  if (extra) for (const u of extra.essential) { paths.add(u); hashes.add(assetKey(extra.integrity[u]));if(!references.has(u))references.set(u,new Set());references.get(u).add(extra.integrity[u]); }
  return {paths,hashes,allImmutable,references,conservative};
}
async function lazyKeys(data, list) {
  const protect = await protectedAssets(data), lazy = new Set(list ? list.lazy : []),record=await goodRecord(data);
  const galleryKeys=new Set(Object.entries(record?.gallery||{}).filter(([u])=>lazy.has(u)).map(([,h])=>assetKey(h)));
  const essentialKeys=new Set([...protect.references.values()].flatMap(h=>[...h].map(assetKey)));
  return (await data.keys()).filter(r => (!protect.paths.has(relative(r)) && (lazy.has(relative(r)) || /^img\/[a-f0-9]{16}\.[a-z0-9]+$/.test(relative(r))))||(galleryKeys.has(relative(r))&&!essentialKeys.has(relative(r))));
}
async function pruneObsolete(data, list) {
  const protect = await protectedAssets(data,list), keep = new Set(list ? list.lazy : []);
  for (const req of await data.keys()) {
    const u = relative(req);
    if (/^(img|vendor)\//.test(u)&&protect.paths.has(u)&&!protect.conservative.has(u)){
      let needed=false;const canonical=await data.match(req);
      for(const h of protect.references.get(u)||[])if(await matchesDigest(canonical,h)&&!await matchesDigest(await data.match(assetKey(h)),h)){needed=true;break}
      if(!needed&&!keep.has(u)){await data.delete(req);continue}
    }
    if ((u.startsWith('asset-') && !protect.allImmutable && !protect.hashes.has(u)) || (/^(img|vendor)\//.test(u) && !protect.paths.has(u) && !keep.has(u))) await data.delete(req);
  }
}
// Saved immutable picture bytes that are (still) optional in the next copy stay as gallery pictures: pictures moved from
// essential to optional, and gallery pictures carried over from the previous copy. Only bytes still stored count; the
// 48 most recently used (cache key order is the persistent LRU) are kept.
async function galleryFor(data,good,next) {
  const old=good&&assetList(good.manifest,good.payload);if(!old||!next)return {};
  const lazy=new Set(next.lazy),byKey=new Map(),add=(u,h)=>{if(lazy.has(u)&&typeof h==='string'&&/^[a-f0-9]{64}$/.test(h)&&(!next.integrity[u]||next.integrity[u]===h))byKey.set(assetKey(h),[u,h])};
  for(const [u,h] of Object.entries(good.gallery||{}))add(u,h);
  for(const u of old.essential)if(u.startsWith('img/'))add(u,old.integrity[u]);
  const ordered=new Map();
  for(const r of await data.keys()){const e=byKey.get(relative(r));if(e){ordered.delete(e[0]);ordered.set(e[0],e[1])}}
  return Object.fromEntries([...ordered].slice(-MAX_LAZY));
}
async function lazyHit(data,url,list){
  const canonical=await data.match(url);if(canonical)return {key:url,response:canonical};
  const record=await goodRecord(data),hash=list?.lazy.includes(url)&&record?.gallery?.[url];
  if(hash){const response=await data.match(assetKey(hash));if(response)return {key:assetKey(hash),response}}
  return null;
}
async function enforceLazyCap(data,list) {
  const keys=await lazyKeys(data,list);
  while(keys.length>MAX_LAZY)await data.delete(keys.shift());
}
async function readyCleanup(data,generation) {
  // Replay the authoritative committed generation, including after a crash before broadcast.
  const record=await goodRecord(data),current=generationOf(record?.payload);
  await broadcast({type:'generation-changed',generation:current,retired:record?.retired||[]});
  if(current!==generation)return snapshot(data,generation);
  if(!(await readJson(data,GOOD))?.bundle)try{await writeGood(data,record)}catch(_){await enforceLazyCap(data,await currentList(data));return snapshot(data,generation)}
  await cleanBundles(data);await data.delete(LIST);
  const list=await currentList(data);
  await pruneObsolete(data,list);await enforceLazyCap(data,list);await pruneShells(list);
  const reserved=await reservePayload(data,record),pointer=await readJson(data,GOOD);
  return {ready:true,assetsReady:true,updating:false,lowSpace:!reserved,pointer:pointer.bundle,saved:list.essential.length,total:list.essential.length};
}
async function removeCandidates(data, except) {
  for (const r of await data.keys()) if (relative(r).startsWith('candidate-') && relative(r) !== except) await data.delete(r);
}
// LRU is persisted by moving an optional entry to the end when it is requested, including cache hits.
async function putWithBudget(data, key, response, list, isLazy = false, target = data, allowAssetGC = true, keepBundle = null) {
  // P6 (F8): a gallery save never re-hashes the essentials (pruneObsolete); it may only drop older gallery pictures.
  allowAssetGC = allowAssetGC && !isLazy;
  let expendable = await lazyKeys(data, list||await currentList(data));
  if (isLazy) while (expendable.length >= MAX_LAZY) await data.delete(expendable.shift());
  let reclaimed = false, reserveReleased=false;
  for (;;) {
    try { await target.put(key, response.clone()); return; }
    catch (error) {
      if (!reclaimed) { await removeCandidates(data,relative(key)); if(relative(key)!==PENDING)await data.delete(PENDING); await cleanBundles(data,keepBundle); if(allowAssetGC)await pruneObsolete(data,list); reclaimed = true; }
      else if(!reserveReleased&&relative(key)!==RESERVE){reserveReleased=true;const reserve=await data.match(RESERVE);if(!isLazy||reserve?.headers.get('X-TB-Reserve-Full')==='false'||(reserve&&Number(reserve.headers.get('X-TB-Reserve-Bytes'))<new TextEncoder().encode(JSON.stringify(await goodRecord(data))).length+2048)){await data.delete(RESERVE);continue}}
      else if (expendable.length) await data.delete(expendable.shift());
      else throw error;
    }
  }
}
// Incoming ciphertext is held by the page. Only its authenticated receipt creates pending state.
// No candidate disk writes: downloading an update must not evict a saved gallery or journal.
async function stagePayload(payload) { return fingerprint(payload); }
async function promotePayload(message) {
  const payload = await checkedPayload(json(message.payload));
  if (!payload || generationOf(payload) !== message.generation || await fingerprint(payload) !== message.fingerprint) {
    await notify(message.generation,{},'failed',{failure:'candidate',failed:1}); return false;
  }
  knownBuilds.set(message.generation,payload.built);
  const data = await caches.open(DATA);let savedNewer=null;
  const accepted=await mutate(async () => {
    const good = await goodRecord(data);
    if (good && await savedFingerprint(good.payload) === message.fingerprint) return true;
    if (good && (good.payload.built > payload.built || (good.retired || []).includes(message.generation))) {
      savedNewer=generationOf(good.payload);await notify(message.generation,{},'different',{reason:'savedNewer',hasSaved:true,currentGeneration:savedNewer}); return false;
    }
    const previous = await pendingRecord(data);
    if (previous && previous.payload.built > payload.built) {
      await notify(message.generation,{},'different',{reason:'pendingNewer',hasSaved:!!good,currentGeneration:generationOf(previous.payload)}); return false;
    }
    if (!previous || previous.verified !== message.fingerprint) pending = {payload,verified:message.fingerprint,manifest:null,baseGood:good&&await savedFingerprint(good.payload)};
    // Authentication does not require a second on-disk payload copy. The receipt supplies exact bytes after a restart.
    await removeCandidates(data);
    return true;
  });
  await followSaved(message.generation,{reason:savedNewer&&'savedNewer',currentGeneration:savedNewer});
  return accepted;
}
// SW-P4-8: when only an older tab learns that a newer copy is saved (for example after a worker crash between the
// pointer switch and its broadcast), also finish that copy's cleanup and broadcast, outside the write lock.
async function followSaved(generation,plan){if(plan&&plan.reason==='savedNewer'&&plan.currentGeneration&&plan.currentGeneration!==generation)await requestPreparation(plan.currentGeneration,true)}
async function matchesDigest(response, expected) {
  return !!response && (!expected || await digest(await response.clone().arrayBuffer()) === expected);
}
// Accounting (anyShell false) counts only this worker's shell cache: another worker's install cache may be incomplete
// and later deleted. P6 (F13): READ paths (serving, olderAvailable) also accept any tb-shell-* entry whose bytes match
// the expected digest, so the old shell keeps working offline after a shell rebuild.
async function matchingShell(url, expected, anyShell = false) {
  const names = [SHELL];
  if (anyShell) for (const name of await caches.keys()) if (name.startsWith('tb-shell-') && name !== SHELL) names.push(name);
  for (const name of names) { const r = await (await caches.open(name)).match(url); if (await matchesDigest(r, expected)) return r; }
  return null;
}
async function pruneShells(list) {
  if (!list || SHELL_FILES.some((u) => !list.integrity[u])) return;
  const current = await caches.open(SHELL);
  for (const url of SHELL_FILES) if (!await matchesDigest(await current.match(url), list.integrity[url])) return;
  for (const name of await caches.keys()) if (name.startsWith('tb-shell-') && name !== SHELL) await caches.delete(name);
}
async function essentialResponse(data,url,hash,anyShell=false) {
  if (!hash) return null;
  const immutable = await data.match(assetKey(hash));
  if (await matchesDigest(immutable,hash)) return immutable;
  if (SHELL_FILES.includes(url)) return matchingShell(url,hash,anyShell);
  const legacy = await data.match(url); return await matchesDigest(legacy,hash) ? legacy : null;
}
// Only call while holding mutate: an installing cache can disappear, so verified
// foreign shell bytes must be persisted independently before they count as saved.
async function copyShells(data,list) {
  if(!list)return;
  for(const url of SHELL_FILES){
    const hash=list.integrity[url];if(!hash||await essentialResponse(data,url,hash))continue;
    for(const name of await caches.keys())if(name.startsWith('tb-shell-')&&name!==SHELL){
      const other=await(await caches.open(name)).match(url);
      if(await matchesDigest(other,hash)){try{await putWithBudget(data,assetKey(hash),other,list)}catch(_){}break}
    }
  }
}
function prepareSnapshot(data,generation){return mutate(async()=>{const r=await targetRecord(data,generation);await copyShells(data,r&&assetList(r.manifest,r.payload));return snapshot(data,generation)})}
const knownBuilds=new Map();
function missingReason(good,generation){return !good?'noCopy':(good.retired||[]).includes(generation)||(knownBuilds.has(generation)&&good.payload.built>knownBuilds.get(generation))?'savedNewer':'differentSaved'}
async function snapshot(data,generation) {
  const record = await targetRecord(data,generation), good = await goodRecord(data);
  if (!record) return {ready:false,different:true,reason:missingReason(good,generation),hasSaved:!!good,currentGeneration:good&&generationOf(good.payload),saved:0,total:0};
  const list = assetList(record.manifest,record.payload);
  const stable = good && generationOf(good.payload) === generation;
  // P6 (F14): the older-copy facts are reported even while the new file list is missing or lags behind the payload.
  const older={updating:!stable,olderAvailable:await olderWorks(data,good,stable),kidChanged:!!good&&good.payload.kid!==record.payload.kid,payloadBytes:new TextEncoder().encode(JSON.stringify(record.payload)).length};
  if (!list) return {ready:false,missing:[],saved:0,total:0,invalidList:true,assetsReady:false,...older};
  const verified = [GOOD,LIST];
  for (const u of list.essential) if (await essentialResponse(data,u,list.integrity[u])) verified.push(u);
  const plan = offlinePlan(record.payload,record.manifest,verified);
  return {...plan,ready:!!stable&&plan.ready,assetsReady:plan.ready,...older};
}
// The saved (older) copy still opens offline when every one of its essentials is readable (any matching shell counts).
async function olderWorks(data,good,stable){
  let olderAvailable=!!good;
  const oldList=good&&assetList(good.manifest,good.payload);
  if(!oldList)olderAvailable=false;
  else if(!stable)for(const u of oldList.essential)if(!await essentialResponse(data,u,oldList.integrity[u],true)){olderAvailable=false;break}
  return olderAvailable;
}
async function commitPending(data,generation) {
  const record = await pendingRecord(data);
  if (!record || generationOf(record.payload) !== generation || !(await snapshot(data,generation)).assetsReady) return false;
  const good = await goodRecord(data), retired = [...(good && good.retired || [])];
  if(good&&(good.payload.built>record.payload.built||retired.includes(generation)||(record.baseGood&&record.baseGood!==await fingerprint(good.payload)&&good.payload.built>=record.payload.built)))return false;
  if (good && generationOf(good.payload) !== generation) retired.push(generationOf(good.payload));
  // Release disposable copies and the reserved update space before writing the immutable bundle.
  await data.delete(PENDING); await removeCandidates(data);
  const list=assetList(record.manifest,record.payload),gallery=await galleryFor(data,good,list);
  await writeGood(data,{payload:record.payload,manifest:record.manifest,retired:retired.slice(-64),gallery});
  pending = null;
  await readyCleanup(data,generation);
  return true;
}
const activity = new Map(), jobs = new Map(), optionalJobs = new Map(), clientGenerations = new Map();
async function mayContinue(generation) {
  return activity.get(generation) !== false && (!self.navigator || self.navigator.onLine !== false) && (await self.clients.matchAll({includeUncontrolled:true})).some(c=>!c.url||c.url.startsWith(scope));
}
async function prepare(generation) {
  const data = await caches.open(DATA); let failure = 'download';
  for (let round=1;round<=3;round++) {
    let plan = await prepareSnapshot(data,generation);
    if (plan.assetsReady && plan.updating) await mutate(()=>commitPending(data,generation));
    plan = await prepareSnapshot(data,generation);
    if (plan.ready)plan=await mutate(()=>readyCleanup(data,generation));
    if (plan.ready || plan.different) { await notify(generation,plan,plan.ready?'ready':'different'); await followSaved(generation,plan); return; }
    if (!await mayContinue(generation)) { await notify(generation,plan,'paused'); return; }
    const record = await targetRecord(data,generation);
    if (!record) { await notify(generation,{},'different',{reason:'noCopy',hasSaved:false}); return; }
    if (!assetList(record.manifest,record.payload)) try {
      const response = await fetchTotal(LIST,LIVE_WAIT_MS);
      if (!response.ok) throw new Error('manifest');
      const raw = await response.json();
      if(raw.generation && raw.generation!==generation){
        const newer=raw.built&&raw.built>record.payload.built;
        if(newer){await notify(generation,plan,'different',{reason:'serverNewer',hasSaved:!!await goodRecord(data),currentGeneration:raw.generation});return}
        await notify(generation,plan,'waiting',{failure:'publish',round});
        if(round<3&&await mayContinue(generation)){await sleep(round*(raw.built?10000:1000));continue}
        await notify(generation,plan,'failed',{failure:'publish',failed:1});return;
      }
      const list = assetList(raw,record.payload);
      if (!list) throw new Error('manifest');
      await mutate(async()=>{
        const next = await pendingRecord(data);
        if (next && generationOf(next.payload)===generation) next.manifest=raw;
        else { // legacy P2 good copy: persist a complete bundle before using this new manifest
          const good=await goodRecord(data);
          if(good&&generationOf(good.payload)===generation) await writeGood(data,{...good,manifest:raw});
        }
      });
    } catch (_) { failure='manifest'; }
    plan = await prepareSnapshot(data,generation);
    if (plan.assetsReady && plan.updating) { await mutate(()=>commitPending(data,generation)); plan=await snapshot(data,generation); }
    if (plan.ready)plan=await mutate(()=>readyCleanup(data,generation));
    if (plan.ready || plan.different) { await notify(generation,plan,plan.ready?'ready':'different'); await followSaved(generation,plan); return; }
    const next = await pendingRecord(data);
    if (next && generationOf(next.payload)===generation && next.manifest) await mutate(async()=>{
      // A journal is useful for resumption but cannot be a prerequisite for making progress under quota.
      try { if((await pendingRecord(data))?.verified===next.verified) await putWithBudget(data,PENDING,json(next),assetList(next.manifest,next.payload)); } catch (_) { /* keep receipt in memory, GOOD is untouched */ }
    });
    await notify(generation,plan,plan.updating?'updating':'saving',{round});
    const missing=plan.missing||[];
    for(let i=0;i<missing.length;i+=PARALLEL) {
      if(!await mayContinue(generation)){await notify(generation,plan,'paused');return}
      await Promise.allSettled(missing.slice(i,i+PARALLEL).map(async u=>{
        try {
          const response=await fetchBounded(u,ASSET_WAIT_MS);if(!response.ok)throw new Error('download');
          await mutate(async()=>{
            const r=await targetRecord(data,generation), list=r&&assetList(r.manifest,r.payload);
            if(!list)return;
            if(!await matchesDigest(response,list.integrity[u]))throw new Error('download');
            try {await putWithBudget(data,assetKey(list.integrity[u]),response,list)} catch(_){throw new Error('storage')}
          });
        } catch(e){failure=e.message==='storage'?'storage':'download'}
        // P6 (F9): a sign of life after each file, so a slow but working save never looks stopped.
        await broadcast({type:'offline-progress',generation});
      }));
      await mutate(async()=>{
        plan=await snapshot(data,generation);
        if(plan.assetsReady&&plan.updating)await commitPending(data,generation);
        plan=await snapshot(data,generation);
        if(plan.ready)plan=await readyCleanup(data,generation)
        await notify(generation,plan,plan.different?'different':plan.ready?'ready':plan.updating?'updating':'saving',{round});
      });
      if(plan.ready||plan.different){await followSaved(generation,plan);return}
    }
    const remaining=plan.total?plan.total-plan.saved:1, decision=retryDecision(round,remaining,await mayContinue(generation),true);
    if(decision.action!=='retry'){if(failure==='storage')await mutate(async()=>{await cleanBundles(data);await reservePayload(data,await goodRecord(data))});await notify(generation,plan,decision.action==='done'?'ready':decision.action,{failure,failed:remaining});return}
    await notify(generation,plan,'retrying',{round,failed:remaining,failure});await sleep(decision.delay);
  }
}
function requestPreparation(generation, online = true) {
  activity.set(generation, online);
  if (!jobs.has(generation)) {
    // P6 (F24): this catch's reserve restore is DEFENSIVE. Inside prepare, the only write that can release the reserve and
    // let its error escape is writeGood, which restores the reserve in its own catch; every other putWithBudget there is
    // wrapped in try/catch. It stays for an unexpected cache error (no known case reaches it; no mutant is registered).
    const job = prepare(generation).catch(async()=>{
      const data=await caches.open(DATA);await mutate(async()=>{await cleanBundles(data);await reservePayload(data,await goodRecord(data))});const plan=await mutate(()=>snapshot(data,generation)),r=await targetRecord(data,generation);
      return notify(generation,plan,'failed',{failure:'storage',failed:Math.max(1,(plan.total||0)-(plan.saved||0)),payloadBytes:r?new TextEncoder().encode(JSON.stringify(r.payload)).length:0});
    });
    jobs.set(generation, job); job.finally(() => jobs.delete(generation)).catch(() => {});
  }
  return jobs.get(generation);
}
function requestOptional(generation,urls,online=true){
  activity.set(generation,online);
  if(optionalJobs.has(generation))return optionalJobs.get(generation);
  const job=(async()=>{
    const data=await caches.open(DATA),list=await currentList(data);
    if(!list||list.generation!==generation)return;
    const wanted=[...new Set(urls)].filter(u=>list.lazy.includes(u)),target=wanted.slice(-MAX_LAZY),attempted=new Set(),success=new Set();
    await broadcast({type:'optional-status',generation,running:true});
    // P7 (C4): besides the sign of life before the first picture and after each one, one every OPTIONAL_BEAT_MS while a picture is slow.
    let beating=true,beat=null;
    const schedule=()=>{beat=setTimeout(async()=>{if(!beating)return;await broadcast({type:'optional-status',generation,running:true});if(beating)schedule()},OPTIONAL_BEAT_MS)};schedule();
    try{
      for(const u of target){
        if(!await mayContinue(generation)||(await currentList(data))?.generation!==generation)break;
        attempted.add(u);lazyFailures.delete(generation+':'+u);await cacheFirst(new Request(new URL(u,scope)),DATA);
        if(await lazyHit(data,u,list))success.add(u);
        await broadcast({type:'optional-status',generation,running:true});
      }
    }finally{
      beating=false;clearTimeout(beat);
      await mutate(async()=>{
        const retained=[],capacity=[],failed=[],waiting=[];
        for(const u of wanted){if(await lazyHit(data,u,list))retained.push(u);else if(!target.includes(u)||success.has(u)||lazyFailures.get(generation+':'+u)==='storage')capacity.push(u);else if(!attempted.has(u))waiting.push(u);else failed.push(u)}
        await broadcast({type:'optional-status',generation,running:false,retained,capacity,failed,pending:waiting,paused:!await mayContinue(generation)});
        await broadcast({type:'offline-warning',generation,urls:[...failed,...waiting],replace:true,capacity,paused:!await mayContinue(generation),pending:waiting,failed});
      });
    }
  })();
  optionalJobs.set(generation,job);job.finally(()=>optionalJobs.delete(generation)).catch(()=>{});return job;
}
async function checkStatus(generation,knownPointer) {
  const data=await caches.open(DATA),pointer=await readJson(data,GOOD);
  const current=pointer?.generation||generationOf((await goodRecord(data))?.payload);
  if(!current)return notify(generation,{},'different',{reason:'noCopy',hasSaved:false});
  if(current!==generation){
    const good=await goodRecord(data),reason=missingReason(good,generation);
    await notify(generation,{},'different',{reason,hasSaved:true,currentGeneration:current});
    if(reason==='savedNewer'&&pointer?.bundle!==knownPointer)await requestPreparation(current,true);
  }else if(pointer.bundle!==knownPointer)await requestPreparation(current,true);
  else await broadcast({type:'offline-heartbeat',generation,pointer:pointer.bundle,lowSpace:!await reserveFull(data),...(await stagedNote(data,generation)||{})});
}
self.addEventListener('message', (event) => {
  const m = event.data;
  if (!m) return;
  if(m.type==='check-status')event.waitUntil(checkStatus(m.generation,m.pointer));
  if (m.type === 'prepare-offline' && typeof m.generation === 'string') event.waitUntil((async()=>{
    await requestPreparation(m.generation,m.online!==false);
    const next=await pendingRecord(await caches.open(DATA));if(next&&m.online!==false&&generationOf(next.payload)!==m.generation)await requestPreparation(generationOf(next.payload),true);
  })());
  if (m.type === 'save-payload') event.waitUntil((async () => {
    const p = await checkedPayload(json(m.payload));
    if (p) try { await stagePayload(p); } catch (_) { await notify(generationOf(p), {}, 'failed', { failure: 'storage', failed: 1, payloadBytes: new TextEncoder().encode(JSON.stringify(p)).length }); }
  })());
  if (m.type === 'retry-lazy' && Array.isArray(m.urls)) event.waitUntil(requestOptional(m.generation,m.urls,m.online!==false));
  if (m.type === 'promote-payload' && event.source) clientGenerations.set(event.source.id, m.generation);
  if (m.type === 'promote-payload') event.waitUntil((async () => {
    if (await promotePayload(m)) await requestPreparation(m.generation, m.online !== false);
  })());
});
// P6 (F8): no response waits for the write lock. Cache writes (shell refresh, copying verified shell bytes, picture
// saves) run after the response, kept alive by the fetch event (defer). Without defer (Retry pictures) they are awaited.
const later = async (defer, job) => { const p = Promise.resolve(job).catch(() => {}); if (defer) defer(p); else await p; };
function scheduleShellCopy(defer, data, list) { return later(defer, mutate(()=>copyShells(data,list))); }
async function savedShell(defer, data, list, rel) {
  await scheduleShellCopy(defer, data, list);
  return list ? essentialResponse(data, rel, list.integrity[rel], true) : matchingShell(rel, undefined, true);
}
async function shellNetworkFirst(request, fallbackKey, defer) {
  const cache = await caches.open(SHELL); let errorResponse;
  try {
    const fresh = await fetchTotal(request, LIVE_WAIT_MS);
    if (fresh.ok) {
      const copy = fresh.clone();
      await later(defer, mutate(async()=>{
        const list=await currentList(await caches.open(DATA)),rel=relative(request)||'index.html';
        if(!list||await matchesDigest(copy,list.integrity[rel]))await cache.put(request,copy);
      }));
      return fresh;
    }
    errorResponse = fresh;
  } catch (_) {}
  const data = await caches.open(DATA), list = await currentList(data);
  return (await savedShell(defer, data, list, fallbackKey || relative(request))) || errorResponse || Response.error();
}
// P6 (F2): with a saved copy, the lock screen gets an answer within LIVE_WAIT_MS. If the new copy is still downloading
// then, the saved copy is served ('slow'), the download carries on in the background and, when complete and newer, is
// kept as a candidate (candidate-<fingerprint>.json, never evicting anything) and announced as a newer build. A later
// slow open serves that downloaded candidate; an offline open always serves the saved copy. Nothing saved: no body limit.
// The website's ETag for a payload already held (the saved copy or a downloaded candidate) makes the request conditional:
// an unchanged copy costs a 304 instead of a download, which matters on slow roaming links.
async function knownEtag(cache, good) {
  const known = good && await readJson(cache, ETAG);
  if (!known || typeof known.etag !== 'string' || typeof known.fingerprint !== 'string') return null;
  if (known.fingerprint === await savedFingerprint(good.payload)) return { etag: known.etag, payload: good.payload, saved: true };
  const staged = await stagedCandidate(cache, good);
  return staged && known.fingerprint === await fingerprint(staged) ? { etag: known.etag, payload: staged, saved: false } : null;
}
function rememberEtag(etag, payload) {
  if (!etag || !payload) return Promise.resolve();
  return fingerprint(payload).then((fp) => mutate(async () => { try { await (await caches.open(DATA)).put(ETAG, json({ etag, fingerprint: fp })); } catch (_) { /* best effort */ } }));
}
async function payloadResponse(request, defer) {
  const cache = await caches.open(DATA), good = await goodRecord(cache); let problem = 'network', errorResponse, timer = null;
  const deadline = good ? new Promise((resolve) => { timer = setTimeout(() => resolve(null), LIVE_WAIT_MS); }) : null;
  try {
    const known = await knownEtag(cache, good);
    const head = await fetchHead(request, good ? LIVE_WAIT_MS : ASSET_WAIT_MS, good ? PAYLOAD_BODY_MS : 0, known ? { 'If-None-Match': known.etag } : null);
    if (head.status === 304 && known) { head.body.catch(() => {}); return json(known.payload); }
    const fresh = deadline ? await Promise.race([head.body, deadline]) : await head.body;
    if (!fresh) {
      problem = head.ok ? 'slow' : 'http-' + head.status;
      if (head.ok) {
        await later(defer, head.body.then(stageDownloaded));
        const staged = await stagedCandidate(cache, good);
        if (staged) return json(staged);
      } else head.body.catch(() => {});
    } else if (!fresh.ok) { problem = 'http-' + fresh.status; errorResponse = fresh; }
    else {
      const candidate = await checkedPayload(fresh);
      if (!candidate) problem = 'damaged';
      else { await later(defer, rememberEtag(head.etag, candidate)); if (good && good.payload.built > candidate.built) return json(good.payload, {'X-TB-Fallback':'older-server'}); return fresh; }
    }
  } catch (_) { /* no connection, or no headers in time */ } finally { if (timer !== null) clearTimeout(timer); }
  return good?json(good.payload,{'X-TB-Fallback':problem}):errorResponse||(problem==='damaged'?new Response('Damaged encrypted copy',{status:502,headers:{'X-TB-Error':'damaged'}}):Response.error());
}
async function stageDownloaded(response) {
  const payload = await checkedPayload(response); if (!payload) return;
  await rememberEtag(response.headers.get('ETag'), payload);
  const key = 'candidate-' + await fingerprint(payload) + '.json'; let base = null;
  await mutate(async () => {
    const data = await caches.open(DATA), good = await goodRecord(data);
    if (!good || !(payload.built > good.payload.built) || (good.retired || []).includes(generationOf(payload))) return;
    if (!await data.match(key)) { await removeCandidates(data, key); try { await data.put(key, json(payload)); } catch (_) { return; } }
    base = generationOf(good.payload);
  });
  if (base) await notify(base, {}, 'different', { reason: 'serverNewer', hasSaved: true, currentGeneration: generationOf(payload), downloaded: true });
}
// P7 (C1): {downloaded, stagedGeneration} when a newer candidate is staged for the saved copy of `generation`, else null.
async function stagedNote(data, generation) {
  try {
    const good = await goodRecord(data);
    if (!good || !generation || generationOf(good.payload) !== generation) return null;
    const staged = await stagedCandidate(data, good);
    return staged ? { downloaded: true, stagedGeneration: generationOf(staged) } : null;
  } catch (_) { return null; }
}
async function stagedCandidate(data, good) {
  let best = null;
  for (const r of await data.keys()) {
    const rel = relative(r); if (!rel.startsWith('candidate-')) continue;
    const saved = await data.match(r), p = saved && await checkedPayload(saved);
    if (p && rel === 'candidate-' + await fingerprint(p) + '.json' && p.built > good.payload.built && !(good.retired || []).includes(generationOf(p)) && (!best || p.built > best.built)) best = p;
  }
  return best;
}
// Versioned HTML references bind a direct vendor request to its exact bytes even before promotion.
// Relative imports keep their paths and use the network first, rather than executing a stale cached library.
async function vendorResponse(request, clientId, defer) {
  const data = await caches.open(DATA), rel = relative(request), url = new URL(request.url, scope);
  const requested = url.searchParams.get('tb-sha'), desired = clientGenerations.get(clientId), list = await currentList(data);
  if (requested && !/^[a-f0-9]{64}$/.test(requested)) return Response.error();
  const expected = requested || (list && (!desired || desired === list.generation) && list.integrity[rel]);
  try {
    const fresh = await fetchBounded(request, ASSET_WAIT_MS);
    if (fresh.ok && await matchesDigest(fresh, expected)) {
      if (list && (!desired || desired === list.generation) && list.essential.includes(rel) && await matchesDigest(fresh, list.integrity[rel])) {
        const copy = fresh.clone();
        await later(defer, mutate(async () => {
          const current = await currentList(data);
          if (current && current.generation === list.generation && current.integrity[rel] === list.integrity[rel] && await matchesDigest(copy, current.integrity[rel]) && !await essentialResponse(data,rel,current.integrity[rel])) await putWithBudget(data, assetKey(current.integrity[rel]), copy, current);
        }).catch(() => notify(list.generation, {}, 'failed', { failure:'storage', failed:1 })));
      }
      return fresh;
    }
  } catch (_) { /* fall back only to matching verified bytes */ }
  const saved=expected&&await essentialResponse(data,rel,expected,true);return saved||Response.error();
}
const lazyFailures=new Map();
async function assetFailure(request, failure, required = false) {
  try {
    const data = await caches.open(DATA), good = await goodRecord(data), list = await currentList(data);
    if (required || (list && list.essential.includes(relative(request)))) {const plan=await snapshot(data,generationOf(good?.payload));await notify(generationOf(good?.payload),plan,plan.ready?'ready':'failed',{failure,storageWarning:plan.ready,failed:1})}
    else {const generation=generationOf(good?.payload),u=relative(request);lazyFailures.set(generation+':'+u,failure);await broadcast({type:'offline-warning',generation,urls:failure==='storage'?[]:[u],capacity:failure==='storage'?[u]:[]})}
  } catch (_) { /* reporting must not break online responses */ }
}
// P6 (F8): gallery saves and LRU moves go through one bounded queue that a single loop drains, one save per lock turn.
// During a fast flick only the LAZY_QUEUE most recent pictures wait; older queued saves are dropped.
const lazyQueue = new Map(); let lazyDrain = null;
async function saveLazy(job) {
  const cache = await caches.open(DATA);
  try {
    await mutate(async () => {
      const now = await currentList(cache);
      if (job.touch) { if (!now || !now.lazy.includes(job.rel)) return; await cache.delete(job.key); try { await putWithBudget(cache, job.key, job.response, now, true); } catch (_) {} return; }
      if (now ? !now.lazy.includes(job.rel) : !/^img\/[a-f0-9]{16}\.[a-z0-9]+$/.test(job.rel)) return;
      if (!await matchesDigest(job.response, now && now.integrity[job.rel])) throw new Error('download');
      await putWithBudget(cache, job.key, job.response, now, true);
    });
  } catch (_) { await assetFailure(job.key, 'storage', false); }
}
function queueLazy(job) {
  const id = relative(job.key); lazyQueue.delete(id); lazyQueue.set(id, job);
  while (lazyQueue.size > LAZY_QUEUE) lazyQueue.delete(lazyQueue.keys().next().value);
  if (!lazyDrain) lazyDrain = (async () => {
    for (;;) { const next = lazyQueue.entries().next(); if (next.done) break; lazyQueue.delete(next.value[0]); try { await saveLazy(next.value[1]); } catch (_) {} }
    lazyDrain = null;
  })();
  return lazyDrain;
}
const lazyBacklog = () => lazyQueue.size;
async function cacheFirst(request, cacheName, clientId, defer) {
  if (cacheName === DATA && relative(request).startsWith('vendor/')) return vendorResponse(request, clientId, defer);
  let cache, hit, required = cacheName !== DATA;
  try { cache = await caches.open(cacheName); hit = await cache.match(request, { ignoreSearch: true }); } catch (_) { /* fetch still works without storage */ }
  const rel = relative(request), dataCache = await caches.open(DATA), list = await currentList(dataCache);
  if (cacheName === SHELL) {
    const saved = await savedShell(defer, dataCache, list, rel);
    if (saved) return saved;
  } else {
    let hitKey=request;
    if(!hit&&list?.lazy.includes(rel)){const saved=await lazyHit(cache,rel,list);if(saved){hit=saved.response;hitKey=saved.key}}
    if(list&&list.essential.includes(rel)){const saved=await essentialResponse(cache,rel,list.integrity[rel]);if(saved)return saved}
    else if(hit){
      if(list&&list.lazy.includes(rel)){const job={key:hitKey,rel,response:hit.clone(),touch:true};await later(defer,defer?queueLazy(job):saveLazy(job))}
      return hit;
    }
  }
  let fresh;
  try { fresh = await fetchBounded(request, ASSET_WAIT_MS); } catch (_) { if (cacheName === DATA) await later(defer, assetFailure(request,'download')); return Response.error(); }
  if (!fresh.ok && cacheName === DATA) await later(defer, assetFailure(request,'download'));
  if (fresh.ok) {
    const copy = fresh.clone();
    if (cacheName === DATA && list && list.lazy.includes(rel) || cacheName === DATA && !list && /^img\/[a-f0-9]{16}\.[a-z0-9]+$/.test(rel)) {
      const job = { key: request, rel, response: copy, touch: false };
      await later(defer, defer ? queueLazy(job) : saveLazy(job));
    } else await later(defer, (async () => { try {
      if (cacheName === DATA) await mutate(async () => {
        const now = await currentList(cache);
        const essential = now && now.essential.includes(rel), lazy = now && now.lazy.includes(rel);
        required = !!essential;
        if (essential || lazy || (!now && /^img\/[a-f0-9]{16}\.[a-z0-9]+$/.test(rel))) {
          if (!await matchesDigest(copy, now && now.integrity[rel])) throw new Error('download');
          await putWithBudget(cache, essential ? assetKey(now.integrity[rel]) : request, copy, now, !essential);
        }
      });
      else await mutate(async () => {
        const now = await currentList(await caches.open(DATA));
        if (!now || await matchesDigest(copy, now.integrity[relative(request)])) await cache.put(request, copy);
      });
    } catch (_) {
      await assetFailure(request,'storage',required);
    } })());
  }
  return fresh; // a quota or other cache failure must never break a successful online picture
}
async function liveManifest(request){
  try{const r=await fetchTotal(request,LIVE_WAIT_MS);if(r.ok)return r}catch(_){}
  const good=await goodRecord(await caches.open(DATA));
  return good&&assetList(good.manifest,good.payload)?json(good.manifest):Response.error();
}
self.addEventListener('fetch', (event) => {
  const request = event.request, url = new URL(request.url);
  if (request.method !== 'GET' || url.origin !== self.location.origin || !url.href.startsWith(scope)) return;
  const rel = relative(request);
  // The event is kept alive (registered synchronously) until the response and every deferred cache write are done.
  const deferred = [], defer = (p) => { deferred.push(p); };
  let work;
  if (rel === 'payload.json') work = payloadResponse(request, defer);
  else if (rel === LIST) work = liveManifest(request);
  else if (request.mode === 'navigate') work = shellNetworkFirst(request, 'index.html', defer);
  else work = cacheFirst(request, rel.startsWith('img/') || rel.startsWith('vendor/') ? DATA : SHELL, event.clientId, defer);
  event.respondWith(work);
  event.waitUntil((async () => { try { await work; } catch (_) {} for (let i = 0; i < deferred.length; i++) await deferred[i]; })());
});
