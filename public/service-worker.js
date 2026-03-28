const CACHE_NAME = 'casino-crepes-v2';
const ASSETS_TO_CACHE = [
  '/',
  '/index.html',
  '/assets/sounds/card_pick_sound.mp3',
  '/assets/sounds/success_sound.mp3',
  '/assets/sounds/cat-laughing-at-you.mp3',
  '/icons/icon-192.png'
];

const OFFLINE_PAGE = `<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1.0, user-scalable=no, viewport-fit=cover"/>
<title>Casino des Crêpes — Hors ligne</title>
<style>
  *{box-sizing:border-box;margin:0;padding:0}
  body{
    font-family:'Georgia',serif;
    background:#0b0b0e;
    color:#f0ede8;
    height:100vh;
    display:flex;
    flex-direction:column;
    align-items:center;
    justify-content:center;
    text-align:center;
    padding:2rem;
  }
  .icon{font-size:4rem;margin-bottom:1rem}
  h1{font-size:1.4rem;color:#c9a84c;margin-bottom:.5rem}
  p{color:#7a7680;font-size:.95rem;line-height:1.5;max-width:300px}
  button{
    margin-top:1.5rem;
    background:#c9a84c;
    color:#0b0b0e;
    border:none;
    padding:.75rem 2rem;
    border-radius:12px;
    font-family:inherit;
    font-size:1rem;
    font-weight:bold;
    cursor:pointer;
  }
  button:active{opacity:.8}
</style>
</head>
<body>
  <div class="icon">🥞</div>
  <h1>Pas de connexion</h1>
  <p>Le Casino des Crêpes a besoin d'internet pour fonctionner. Vérifie ta connexion et réessaie.</p>
  <button onclick="location.reload()">Réessayer</button>
</body>
</html>`;

// Install — cache core assets + offline page
self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => {
      cache.put('/offline', new Response(OFFLINE_PAGE, {
        headers: { 'Content-Type': 'text/html; charset=utf-8' }
      }));
      return cache.addAll(ASSETS_TO_CACHE);
    })
  );
  self.skipWaiting();
});

// Activate — clean old caches
self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((keys) =>
      Promise.all(keys.filter((k) => k !== CACHE_NAME).map((k) => caches.delete(k)))
    )
  );
  self.clients.claim();
});

// Fetch — network first, fallback to cache, then offline page
self.addEventListener('fetch', (event) => {
  if (event.request.method !== 'GET') return;

  const url = new URL(event.request.url);

  // Let API/auth requests fail naturally so the app can show its own errors
  if (url.pathname.startsWith('/api/') || url.pathname.startsWith('/auth/')) return;

  // For page navigations — show offline page if network fails
  if (event.request.mode === 'navigate') {
    event.respondWith(
      fetch(event.request)
        .then((response) => {
          if (response.ok) {
            const clone = response.clone();
            caches.open(CACHE_NAME).then((cache) => cache.put(event.request, clone));
          }
          return response;
        })
        .catch(() => caches.match('/offline'))
    );
    return;
  }

  // For other assets — network first, cache fallback
  event.respondWith(
    fetch(event.request)
      .then((response) => {
        if (response.ok) {
          const clone = response.clone();
          caches.open(CACHE_NAME).then((cache) => cache.put(event.request, clone));
        }
        return response;
      })
      .catch(() => caches.match(event.request))
  );
});
