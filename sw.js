// Service worker for the Trip board web app. Keeps the lock screen, the encrypted file and the pictures on the
// device so the app opens offline (for example on a plane or in China without a connection).
const VERSION = 'tb-c5c02f69cb30';
const CORE = ['./', 'index.html', 'manifest.webmanifest', 'icon-192.png', 'icon-512.png', 'apple-touch-icon.png'];

self.addEventListener('install', (event) => {
  event.waitUntil((async () => {
    const cache = await caches.open(VERSION);
    await cache.addAll(CORE);
    try { await cache.add(new Request('payload.json', { cache: 'reload' })); } catch (_) { /* not set up yet */ }
    await self.skipWaiting();
  })());
});

self.addEventListener('activate', (event) => {
  event.waitUntil((async () => {
    for (const key of await caches.keys()) if (key !== VERSION) await caches.delete(key);
    await self.clients.claim();
    try {
      const list = await (await fetch('precache.json', { cache: 'no-store' })).json();
      const cache = await caches.open(VERSION);
      await Promise.allSettled(list.map((url) => cache.add(url)));
    } catch (_) { /* pictures will be cached as they are used */ }
  })());
});

async function networkFirst(request, fallbackKey) {
  const cache = await caches.open(VERSION);
  try {
    const fresh = await fetch(request, { cache: 'no-store' });
    if (fresh && fresh.ok) cache.put(request, fresh.clone());
    return fresh;
  } catch (_) {
    return (await cache.match(request, { ignoreSearch: true })) || (fallbackKey && (await cache.match(fallbackKey))) || Response.error();
  }
}

async function cacheFirst(request) {
  const cache = await caches.open(VERSION);
  const hit = await cache.match(request, { ignoreSearch: true });
  if (hit) return hit;
  try {
    const fresh = await fetch(request);
    if (fresh && fresh.ok) cache.put(request, fresh.clone());
    return fresh;
  } catch (_) {
    return Response.error();
  }
}

self.addEventListener('fetch', (event) => {
  const request = event.request;
  if (request.method !== 'GET') return;
  const url = new URL(request.url);
  if (url.origin !== self.location.origin) return;
  const name = url.pathname.split('/').pop();
  if (name === 'payload.json' || name === 'precache.json') { event.respondWith(networkFirst(request)); return; }
  if (request.mode === 'navigate') { event.respondWith(networkFirst(request, 'index.html')); return; }
  event.respondWith(cacheFirst(request));
});
