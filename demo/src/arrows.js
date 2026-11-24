/* Draws the active step's data flows as arrows over the stage, from one item to another,
   measured from the DOM. Every arrow runs through the lane between the two sides, each on
   its own track: out of an item on the left by its right edge, into an item on the right by
   its left edge. A filled number sits at its base, an outlined one near its tip, set back
   from the head. Hovering an arrow or a number shows the flow's line from the numbered list
   and thickens the arrow. An item inside a closed section or row is drawn to that row's
   title. Below 1280px the lane is hidden and the numbered list under the picture stands in. */
(function () {
  'use strict';
  var PSS = window.PSS;
  var NS = 'http://www.w3.org/2000/svg';
  var DASH = { read: '5 4', push: '1.5 3' };
  var RD = { public: 'pub', user: 'usr', shared: 'shr', operator: 'opr' };
  var flows = [], raf = 0, tipEl = null;

  function el(svg, name, attrs, style) {
    var e = document.createElementNS(NS, name);
    for (var a in attrs) e.setAttribute(a, attrs[a]);
    if (style) for (var s in style) e.style[s] = style[s];
    svg.appendChild(e);
    return e;
  }

  // what each flow says when hovered: its line from the numbered list (one source for both)
  function describe(f) {
    var li = document.querySelectorAll('#flowlist li')[f.n - 1];
    return f.n + ' · ' + f.k + ': ' + (li ? li.children[2].textContent : f.t);
  }

  function draw() {
    var stage = document.getElementById('stage');
    var svg = document.getElementById('ov');
    var lane = document.getElementById('lane');
    if (!stage || !svg || !lane) return;
    while (svg.firstChild) svg.removeChild(svg.firstChild);
    if (!tipEl || !stage.contains(tipEl)) {
      tipEl = document.createElement('div');
      tipEl.className = 'tipbox';
      tipEl.hidden = true;
      stage.appendChild(tipEl);
    }
    var on = window.innerWidth >= 1280 && getComputedStyle(lane).display !== 'none';
    if (!on || !flows.length) {
      svg.setAttribute('width', 0); svg.setAttribute('height', 0);
      if (on) stage.style.setProperty('--lane', '40px');
      return;
    }
    var sr = stage.getBoundingClientRect();
    svg.setAttribute('width', sr.width);
    svg.setAttribute('height', sr.height);
    var lr = lane.getBoundingClientRect();
    var laneL = lr.left - sr.left, laneR = lr.right - sr.left;

    function move(ev) {
      var r = stage.getBoundingClientRect();
      tipEl.style.left = Math.max(0, Math.min(ev.clientX - r.left + 14, r.width - 330)) + 'px';
      tipEl.style.top = (ev.clientY - r.top + 14) + 'px';
    }
    function wire(e, f, col) {
      e.style.pointerEvents = e.tagName === 'path' ? 'stroke' : 'auto';
      e.style.cursor = 'help';
      function thick(v) { svg.querySelectorAll('[data-f="' + f.n + '"]').forEach(function (p) { p.style.strokeWidth = v ? '4.5' : ''; }); }
      e.addEventListener('mouseenter', function (ev) { tipEl.textContent = describe(f); tipEl.style.setProperty('--c', col); tipEl.hidden = false; move(ev); thick(true); });
      e.addEventListener('mousemove', move);
      e.addEventListener('mouseleave', function () { tipEl.hidden = true; thick(false); });
    }
    function hit(d, f, col) {
      wire(el(svg, 'path', { d: d, fill: 'none', 'stroke-width': 12 }, { stroke: 'transparent' }), f, col);
    }
    function tipBadge(x, y, f, col) {
      var c = el(svg, 'circle', { cx: x, cy: y, r: 7, 'stroke-width': 1.5 }, { fill: 'var(--panel)', stroke: col });
      var t = el(svg, 'text', { x: x, y: y + 3.2, 'text-anchor': 'middle', 'font-size': 9, 'font-weight': 700 }, { fill: col, fontFamily: 'var(--mono)', pointerEvents: 'none' });
      t.textContent = f.n;
      wire(c, f, col);
    }
    function box(id) {
      var e = document.getElementById(PSS.domId(id));
      if (!e) return null;
      // inside a closed <details> an item has no box: use the outermost closed one's title
      var d = e.closest('details:not([open])'), up;
      if (d) {
        while (d.parentElement && (up = d.parentElement.closest('details:not([open])'))) d = up;
        e = d.querySelector(':scope > summary') || d;
      }
      var r = e.getBoundingClientRect();
      if (!r.width && !r.height) return null;
      var b = { l: r.left - sr.left, r: r.right - sr.left, t: r.top - sr.top, b: r.bottom - sr.top };
      b.side = b.l >= laneR - 1 ? 'R' : 'L';
      b.y = b.t + Math.min(12, (b.b - b.t) / 2);
      return b;
    }
    // bases and tips on one element get separate slots: bases from the top, tips below them,
    // so a number never sits beside another arrow's head
    var outs = Object.create(null), used = Object.create(null), tips = Object.create(null), bases = Object.create(null);
    flows.forEach(function (f) { outs[f.from] = (outs[f.from] || 0) + 1; });
    function anchor(b, id, isTip) {
      var key = id + (isTip ? '>' : '<');
      used[key] = (used[key] || 0) + 1;
      var slot = isTip ? (outs[id] || 0) + used[key] - 1 : used[key] - 1;
      var step = b.b - b.t > 60 ? 16 : 6;
      return Math.min(b.b - 3, b.y + slot * step);
    }
    var track = 0;
    flows.forEach(function (f) {
      var a = box(f.from);
      if (!a) return;
      var col = 'var(--' + f.c + ')';
      var x = laneR - 12 - track * 7;
      track++;
      var ya = anchor(a, f.from);
      var sx = a.side === 'L' ? a.r : a.l;
      f.to.forEach(function (id) {
        var b = box(id);
        if (!b) return;
        var yb = anchor(b, id, true);
        var ex = b.side === 'L' ? b.r : b.l;
        var dir = ex > x ? 1 : -1;
        var d = 'M' + sx + ' ' + ya + ' H' + x + ' V' + yb + ' H' + (ex - dir * 6);
        el(svg, 'path', { d: d, fill: 'none', 'stroke-width': f.k === 'call' ? 2.4 : 1.7, 'stroke-dasharray': DASH[f.k] || '', 'data-f': f.n, 'class': 'fl' }, { stroke: col });
        hit(d, f, col);
        el(svg, 'path', { d: 'M' + ex + ' ' + yb + ' l' + (-dir * 7) + ' -4 v8 z', 'class': 'fl' }, { fill: col });
        // several heads on one item: their numbers step back along the line, one per arrow
        var tn = tips[id] = (tips[id] || 0) + 1;
        tipBadge(ex - dir * (18 + (outs[id] || 0) * 17 + (tn - 1) * 15), yb - 9, f, col);
      });
      var bn = bases[f.from] = (bases[f.from] || 0) + 1;
      var bx = sx + (a.side === 'L' ? 1 : -1) * (9 + (bn - 1) * 17);
      var badge = el(svg, 'circle', { cx: bx, cy: ya, r: 8 }, { fill: col });
      wire(badge, f, col);
      var num = el(svg, 'text', { x: bx, y: ya + 3.5, 'text-anchor': 'middle', 'font-size': 10, 'font-weight': 700 }, { fill: 'var(--panel)', fontFamily: 'var(--mono)', pointerEvents: 'none' });
      num.textContent = f.n;
    });
    // the lane is only as wide as its tracks need: no labels live there
    var want = 26 + track * 7;
    if (Math.abs((laneR - laneL) - want) > 2) { stage.style.setProperty('--lane', want + 'px'); later(); }
  }

  function later() { cancelAnimationFrame(raf); raf = requestAnimationFrame(draw); }

  PSS.arrows = {
    set: function (step) {
      flows = (step.flows || []).map(function (f, i) {
        return { n: i + 1, k: f.kind, from: f.from, to: f.to || [], c: RD[f.reader] || 'pub', t: PSS.plain(f.payload || f.text) };
      });
      later();
    },
    redraw: later
  };

  window.addEventListener('resize', later);
  // sections and rows open and close: redraw (toggle does not bubble, so listen in capture)
  document.addEventListener('toggle', later, true);
  if (window.ResizeObserver) {
    var ro = new ResizeObserver(later);
    document.addEventListener('DOMContentLoaded', function () { var m = document.getElementById('main'); if (m) ro.observe(m); });
    PSS.arrows.observe = function (node) { ro.observe(node); };
  }
})();
