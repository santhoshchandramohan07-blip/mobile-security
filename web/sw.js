// AegisShield Mobile Guardian - Offline App Service Worker
const CACHE_NAME = 'aegis-shield-v9';

const PRECACHE_ASSETS = [
  '/',
  '/index.html?v=9',
  '/style.css?v=9',
  '/app.js?v=9',
  '/manifest.json',
  '/icon-192.png',
  '/icon-512.png'
];

// Pre-cache static shell on installation
self.addEventListener('install', (event) => {
  self.skipWaiting();
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => {
      console.log('[SW] Installing latest AegisShield shell...');
      return cache.addAll(PRECACHE_ASSETS).catch((err) => {
        console.warn('[SW] Pre-cache partial error:', err);
      });
    })
  );
});

// Activate and purge old caches immediately
self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((keys) => {
      return Promise.all(
        keys.map((key) => {
          if (key !== CACHE_NAME) {
            console.log('[SW] Purging legacy cache:', key);
            return caches.delete(key);
          }
        })
      );
    }).then(() => self.clients.claim())
  );
});

// Network-First fetch strategy: always try network first for fresh live telemetry and scripts
self.addEventListener('fetch', (event) => {
  const url = new URL(event.request.url);

  // Ignore non-HTTP(S) schemes (e.g. chrome-extension, ws)
  if (!url.protocol.startsWith('http')) return;

  // API calls: Network only (with offline status fallback)
  if (url.pathname.startsWith('/api/')) {
    event.respondWith(
      fetch(event.request).catch(async () => {
        return new Response(JSON.stringify({ error: 'Offline', offline: true }), {
          status: 503,
          headers: { 'Content-Type': 'application/json' }
        });
      })
    );
    return;
  }

  // Static Assets & App Shell: Network-First, fallback to Cache
  event.respondWith(
    fetch(event.request)
      .then((networkResponse) => {
        if (networkResponse && networkResponse.status === 200 && networkResponse.type === 'basic') {
          const responseToCache = networkResponse.clone();
          caches.open(CACHE_NAME).then((cache) => {
            cache.put(event.request, responseToCache);
          });
        }
        return networkResponse;
      })
      .catch(() => {
        // Fallback to cache if network is down
        return caches.match(event.request).then((cachedResponse) => {
          if (cachedResponse) return cachedResponse;
          if (event.request.mode === 'navigate') {
            return caches.match('/index.html') || caches.match('/');
          }
        });
      })
  );
});

// Handle notification tap
self.addEventListener('notificationclick', (event) => {
  event.notification.close();
  const pkg = event.notification.data && event.notification.data.package_name ? event.notification.data.package_name : '';
  const targetUrl = pkg ? `/?focus=${encodeURIComponent(pkg)}` : '/';

  event.waitUntil(
    clients.matchAll({ type: 'window', includeUncontrolled: true }).then((clientList) => {
      for (const client of clientList) {
        if ('focus' in client) {
          client.focus();
          if (pkg) {
            client.postMessage({ action: 'FOCUS_APP', package_name: pkg });
          }
          return;
        }
      }
      if (clients.openWindow) {
        return clients.openWindow(targetUrl);
      }
    })
  );
});
