(() => {
  const screen = document.getElementById('screen-auth');
  const video = document.getElementById('auth-background-video');
  const toggle = document.getElementById('auth-video-toggle');
  const motion = matchMedia('(prefers-reduced-motion: reduce)');
  let wantsPlayback = !motion.matches;
  function updateButton() {
    if (!toggle) return;
    toggle.textContent = video.paused ? '▶' : 'Ⅱ';
    toggle.setAttribute('aria-label', video.paused ? 'Lire la vidéo' : 'Mettre la vidéo en pause');
    toggle.setAttribute('aria-pressed', String(!video.paused));
  }
  function syncPlayback() {
    if (wantsPlayback && !screen.classList.contains('hidden') && !document.hidden) {
      video.play().catch(updateButton);
    } else {
      video.pause();
    }
    updateButton();
  }
  if (toggle) toggle.addEventListener('click', () => { wantsPlayback = video.paused; syncPlayback(); });
  video.addEventListener('play', updateButton);
  video.addEventListener('pause', updateButton);
  motion.addEventListener('change', () => { wantsPlayback = !motion.matches; syncPlayback(); });
  document.addEventListener('visibilitychange', syncPlayback);
  new MutationObserver(syncPlayback).observe(screen, { attributes: true, attributeFilter: ['class'] });
  syncPlayback();
})();
