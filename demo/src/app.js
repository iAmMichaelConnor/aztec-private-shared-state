/* The page: tabs, the step (Prev / Next / Play, ← →, deep links #<tab>-<step>), picking an
   item, and reference links that open, scroll to and flash the thing they name. */
(function () {
  'use strict';
  var PSS = window.PSS;
  var data = null;
  var view = { tab: null, k: 1, picked: null, playing: false, secOpen: Object.create(null) };
  var timer = 0;
  var reduce = window.matchMedia ? window.matchMedia('(prefers-reduced-motion: reduce)') : { matches: false };
  var PLAY_MS = 2600;

  var main = document.getElementById('main');
  var tabsEl = document.getElementById('tabs');
  var note = document.getElementById('topnote');

  function tabById(id) { return data.tabs.filter(function (t) { return t.id === id; })[0]; }
  function scenario() { var t = tabById(view.tab); return t && t.scenario ? data.scenarios[t.scenario] : null; }

  function renderTabs() {
    tabsEl.innerHTML = data.tabs.map(function (t) {
      var on = t.id === view.tab;
      return '<button type="button" class="tab' + (on ? ' on' : '') + (t.scenario ? '' : ' next') + '" data-tab="' + PSS.esc(t.id) + '"' + (on ? ' aria-current="page"' : '') + '>' +
        PSS.esc(t.label) + '<small>' + PSS.esc(t.path) + (t.scenario ? '' : ' · coming next') + '</small></button>';
    }).join('');
  }

  function render() {
    renderTabs();
    var t = tabById(view.tab);
    var s = scenario();
    if (!s) {
      PSS.renderNext(main, t);
      note.textContent = 'Coming next.';
      PSS.arrows.set({ flows: [] });
      return;
    }
    if (view.k < 1) view.k = 1;
    if (view.k > s.steps.length) view.k = s.steps.length;
    PSS.render(main, data, view);
    note.innerHTML = PSS.text(s.title || '', s) + ' · values are illustrative · on wide screens the step\'s flows are arrows: hover one to see what it carries';
    PSS.arrows.set(s.steps[view.k - 1]);
    document.title = s.label + ' ' + view.k + ' · PSS step by step';
  }

  // ---------------------------------------------------------------- routing
  function hashFor() { return '#' + view.tab + (scenario() ? '-' + view.k : ''); }
  function writeHash() {
    var h = hashFor();
    if (location.hash !== h) history.replaceState(null, '', h);
  }
  function readHash() {
    var h = decodeURIComponent(location.hash.slice(1));
    if (!h || h.slice(0, 2) === 'x-') return false;
    var m = /^(.*?)(?:-(\d+))?$/.exec(h);
    var t = tabById(m[1]);
    if (!t) return false;
    if (t.id !== view.tab) { view.picked = null; view.secOpen = Object.create(null); }
    view.tab = t.id;
    view.k = m[2] ? parseInt(m[2], 10) : 1;
    return true;
  }

  function go(k, keepPlaying) {
    var s = scenario();
    if (!s) return;
    k = Math.max(1, Math.min(s.steps.length, k));
    if (!keepPlaying) stop();
    if (k === view.k && !keepPlaying) return;
    view.k = k;
    view.picked = null;
    render();
    writeHash();
  }

  // ---------------------------------------------------------------- play
  function stop() {
    clearTimeout(timer);
    if (view.playing) { view.playing = false; var b = main.querySelector('[data-go="play"]'); if (b) { b.textContent = 'Play'; b.classList.remove('on'); b.setAttribute('aria-pressed', 'false'); } }
  }
  function tick() {
    var s = scenario();
    if (!s || !view.playing) return;
    if (view.k >= s.steps.length) { stop(); return; }
    go(view.k + 1, true);
    timer = setTimeout(tick, reduce.matches ? PLAY_MS * 1.5 : PLAY_MS);
  }
  function play() {
    var s = scenario();
    if (!s) return;
    if (view.playing) { stop(); return; }
    view.playing = true;
    if (view.k >= s.steps.length) { view.k = 0; }
    tick();
    var b = main.querySelector('[data-go="play"]');
    if (b) { b.textContent = 'Pause'; b.classList.add('on'); b.setAttribute('aria-pressed', 'true'); }
  }

  // ---------------------------------------------------------------- references: open, scroll, flash
  function reveal(id) {
    var t = document.getElementById(PSS.domId(id));
    if (!t) return false;
    // open the row itself when it is one, and every closed section or row around it
    var own = t.matches('details') ? t : t.querySelector(':scope > details');
    if (own) own.open = true;
    for (var p = t.parentElement && t.parentElement.closest('details'); p; p = p.parentElement && p.parentElement.closest('details')) p.open = true;
    t.scrollIntoView({ block: 'center', behavior: reduce.matches ? 'auto' : 'smooth' });
    var target = t.matches('details.sec') ? t : t;
    target.classList.remove('flash', 'fade');
    void target.offsetWidth;
    target.classList.add('flash');
    if (reduce.matches) setTimeout(function () { target.classList.add('fade'); }, 60);
    clearTimeout(target._flash);
    target._flash = setTimeout(function () { target.classList.remove('flash', 'fade'); }, 2600);
    PSS.arrows.redraw();
    return true;
  }

  // ---------------------------------------------------------------- events
  document.addEventListener('click', function (ev) {
    var tgt = ev.target;
    if (!tgt.closest) return;
    var ref = tgt.closest('a.ref');
    if (ref) {
      ev.preventDefault();
      var id = ref.getAttribute('data-ref');
      if (id) { stop(); reveal(id); }
      return;
    }
    var tab = tgt.closest('[data-tab]');
    if (tab) {
      stop();
      view.tab = tab.getAttribute('data-tab'); view.k = 1; view.picked = null; view.secOpen = Object.create(null);
      render(); writeHash();
      return;
    }
    var dot = tgt.closest('[data-step]');
    if (dot) { go(parseInt(dot.getAttribute('data-step'), 10)); return; }
    var btn = tgt.closest('[data-go]');
    if (btn) {
      var g = btn.getAttribute('data-go');
      if (g === 'prev') go(view.k - 1);
      else if (g === 'next') go(view.k + 1);
      else if (g === 'play') play();
      return;
    }
    if (tgt.closest('summary')) return;
    var item = tgt.closest('[data-item]');
    if (item && main.contains(item)) {
      view.picked = item.getAttribute('data-item');
      var y = window.scrollY;
      render();
      window.scrollTo(0, y);
    }
  });

  // a section the reader opened or closed stays so while stepping through the same tab
  document.addEventListener('toggle', function (ev) {
    var d = ev.target;
    if (d && d.getAttribute && d.getAttribute('data-sec')) view.secOpen[d.getAttribute('data-sec')] = d.open;
  }, true);

  document.addEventListener('keydown', function (ev) {
    if (ev.altKey || ev.ctrlKey || ev.metaKey) return;
    var tag = (ev.target.tagName || '').toLowerCase();
    if (tag === 'input' || tag === 'textarea' || tag === 'select') return;
    var s = scenario();
    if (!s) return;
    if (ev.key === 'ArrowRight') { go(view.k + 1); ev.preventDefault(); }
    else if (ev.key === 'ArrowLeft') { go(view.k - 1); ev.preventDefault(); }
    else if (ev.key === 'Home') { go(1); ev.preventDefault(); }
    else if (ev.key === 'End') { go(s.steps.length); ev.preventDefault(); }
  });

  window.addEventListener('hashchange', function () {
    if (readHash()) { stop(); render(); }
  });

  // ---------------------------------------------------------------- start
  PSS.load().then(function (d) {
    data = d;
    if (!readHash()) { view.tab = data.tabs[0].id; view.k = 1; }
    render();
    writeHash();
  }).catch(function (e) {
    note.textContent = 'Could not load the data: ' + e.message + '. Serve the repository root (python3 -m http.server) and open /demo/, or build demo/dist/index.html.';
    if (window.console) console.error(e);
  });
})();
