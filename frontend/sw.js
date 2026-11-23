/**
 * AnswerChain Offline Verification Service Worker.
 * Caches core verification assets for 100% offline access in airplane mode.
 */

const CACHE_NAME = 'answerchain-verify-v2';
const OFFLINE_ASSETS = [
    '/verify/index.html',
    '/verify',
    '/style.css',
    '/api.js',
    '/offline-verifier.js',
    '/vendor/jsqr/jsQR.min.js'
];

self.addEventListener('install', (event) => {
    event.waitUntil(
        caches.open(CACHE_NAME).then((cache) => {
            return cache.addAll(OFFLINE_ASSETS).catch((err) => {
                console.warn('Service worker cache partial failure:', err);
            });
        }).then(() => self.skipWaiting())
    );
});

self.addEventListener('activate', (event) => {
    event.waitUntil(
        caches.keys().then((keys) => {
            return Promise.all(
                keys.map((key) => {
                    if (key !== CACHE_NAME) {
                        return caches.delete(key);
                    }
                })
            );
        }).then(() => self.clients.claim())
    );
});

self.addEventListener('fetch', (event) => {
    const url = new URL(event.request.url);

    // Only intercept same-origin GET requests for static verify assets
    if (event.request.method !== 'GET' || url.origin !== location.origin) {
        return;
    }

    // Do not cache active /api/ requests in SW (let API calls fail naturally when offline)
    if (url.pathname.startsWith('/api/')) {
        return;
    }

    event.respondWith(
        fetch(event.request)
            .then((networkResponse) => {
                // Update cache dynamically for static files
                if (networkResponse && networkResponse.status === 200) {
                    const responseClone = networkResponse.clone();
                    caches.open(CACHE_NAME).then((cache) => {
                        cache.put(event.request, responseClone);
                    });
                }
                return networkResponse;
            })
            .catch(() => {
                // Fall back to cache when offline with query string tolerance
                return caches.match(event.request, { ignoreSearch: true }).then((cachedResponse) => {
                    if (cachedResponse) {
                        return cachedResponse;
                    }
                    if (event.request.mode === 'navigate' || url.pathname.includes('/verify')) {
                        return caches.match('/verify/index.html');
                    }
                    return new Response('Offline: Network unavailable', { status: 503, statusText: 'Offline' });
                });
            })
    );
});
