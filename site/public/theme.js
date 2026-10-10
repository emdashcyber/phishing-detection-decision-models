(function () {
  var root = document.documentElement;
  var KEY = 'emdash-theme';
  var stored = null;
  try { stored = localStorage.getItem(KEY); } catch (e) {}
  if (stored === 'light' || stored === 'dark') root.setAttribute('data-theme', stored);

  var dark = window.matchMedia('(prefers-color-scheme: dark)');
  var current = function () { return root.getAttribute('data-theme') || (dark.matches ? 'dark' : 'light'); };

  // theme-color metas cannot follow data-theme via CSS, so pin them to the active theme.
  var paint = function () {
    var t = current();
    var metas = document.querySelectorAll('meta[name="theme-color"]');
    for (var i = 0; i < metas.length; i++) {
      metas[i].setAttribute('media', 'all');
      metas[i].setAttribute('content', t === 'dark' ? '#0a1420' : '#ffffff');
    }
  };

  document.addEventListener('DOMContentLoaded', function () {
    var btn = document.getElementById('theme-toggle');
    if (!btn) return;
    btn.hidden = false;
    var sync = function () { btn.setAttribute('aria-pressed', current() === 'dark' ? 'true' : 'false'); };
    sync();
    if (stored) paint();
    btn.addEventListener('click', function () {
      var next = current() === 'dark' ? 'light' : 'dark';
      root.setAttribute('data-theme', next);
      try { localStorage.setItem(KEY, next); } catch (e) {}
      sync();
      paint();
    });
    dark.addEventListener('change', function () { if (!root.getAttribute('data-theme')) sync(); });
  });
})();
