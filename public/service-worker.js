const CACHE_NAME = 'casino-crepes-v3';
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
    overflow:hidden;
  }
  .offline-cards{
    display:flex;gap:10px;margin-bottom:2rem;perspective:600px;
  }
  .offline-card{
    width:56px;height:82px;border-radius:8px;
    display:flex;align-items:center;justify-content:center;
    font-size:28px;box-shadow:0 6px 20px rgba(0,0,0,.5);
    animation:float 3s ease-in-out infinite;
  }
  .offline-card:nth-child(1){
    background:linear-gradient(135deg,#1a3a6e,#0e2246);border:2px solid #2a5298;
    animation-delay:0s;
  }
  .offline-card:nth-child(2){
    background:#fdfaf4;color:#c0252a;border:1px solid #e8dfc4;
    animation-delay:.4s;
  }
  .offline-card:nth-child(3){
    background:linear-gradient(135deg,#1a3a6e,#0e2246);border:2px solid #2a5298;
    animation-delay:.8s;
  }
  @keyframes float{
    0%,100%{transform:translateY(0) rotate(0deg)}
    50%{transform:translateY(-12px) rotate(2deg)}
  }
  .icon{font-size:3rem;margin-bottom:.75rem}
  h1{font-size:1.4rem;color:#c9a84c;margin-bottom:.5rem;letter-spacing:1px}
  p{color:#7a7680;font-size:.9rem;line-height:1.6;max-width:300px}
  .status{
    margin-top:1rem;font-size:.8rem;color:#7a7680;font-family:sans-serif;
    display:flex;align-items:center;gap:6px;
  }
  .dot{width:8px;height:8px;border-radius:50%;background:#e04444;
    animation:pulse 2s infinite;}
  @keyframes pulse{0%,100%{opacity:1}50%{opacity:.3}}
  button{
    margin-top:1.5rem;
    background:linear-gradient(135deg,#c9a84c,#b8943f);
    color:#0b0b0e;border:none;
    padding:.75rem 2.5rem;border-radius:12px;
    font-family:inherit;font-size:1rem;font-weight:bold;
    cursor:pointer;letter-spacing:.5px;
    box-shadow:0 4px 16px rgba(201,168,76,.3);
    transition:transform .15s,box-shadow .15s;
  }
  button:hover{transform:translateY(-1px);box-shadow:0 6px 20px rgba(201,168,76,.4)}
  button:active{transform:scale(.97);opacity:.9}
  .bg-suits{
    position:fixed;inset:0;pointer-events:none;overflow:hidden;opacity:.06;
  }
  .bg-suits span{
    position:absolute;font-size:32px;color:#c9a84c;
    animation:drift 15s linear infinite;
  }
  @keyframes drift{
    0%{transform:translateY(100vh) rotate(0deg);opacity:0}
    10%{opacity:1}90%{opacity:1}
    100%{transform:translateY(-100px) rotate(360deg);opacity:0}
  }
</style>
</head>
<body>
  <div class="bg-suits" id="bg"></div>
  <div class="offline-cards">
    <div class="offline-card">🂠</div>
    <div class="offline-card">♥</div>
    <div class="offline-card">🂠</div>
  </div>
  <div class="icon">🥞</div>
  <h1>Pas de connexion</h1>
  <p>Le Casino des Crêpes a besoin d'internet pour fonctionner. Vérifie ta connexion et réessaie.</p>
  <div class="status"><span class="dot"></span>Hors ligne</div>
  <button onclick="location.reload()">Réessayer</button>
  <script>
    var suits=['♠','♥','♦','♣'],bg=document.getElementById('bg');
    for(var i=0;i<20;i++){
      var s=document.createElement('span');
      s.textContent=suits[i%4];
      s.style.left=Math.random()*100+'%';
      s.style.animationDelay=-Math.random()*15+'s';
      s.style.fontSize=(20+Math.random()*24)+'px';
      if(i%4===1||i%4===2)s.style.color='rgba(180,40,40,.8)';
      bg.appendChild(s);
    }
    window.addEventListener('online',function(){location.reload()});
  </script>
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
