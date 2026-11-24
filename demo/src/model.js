/* The model: loading the data, the reference registry, the text markup and the replay of a
   scenario's steps into the state shown at step k. No DOM here except the text markup's
   HTML strings. */
(function () {
  'use strict';
  var PSS = window.PSS = window.PSS || {};
  // maps keyed by ids have no prototype: an id like `constructor` must not find Object's
  function dict() { return Object.create(null); }
  PSS.dict = dict;

  // ---------------------------------------------------------------- loading
  function getJSON(url) {
    return fetch(url, { cache: 'no-cache' }).then(function (r) {
      if (!r.ok) throw new Error(url + ': ' + r.status);
      return r.json();
    });
  }

  // the parts of design-space.json the brick panel reads (build.py's brick_data)
  function brickData(ds) {
    return {
      statuses: Object.keys(ds.statuses || {}).reduce(function (o, k) { o[k] = ds.statuses[k].label || k; return o; }, {}),
      axes: (ds.axes || []).map(function (a) {
        return { id: a.id, label: a.label || a.id, question: a.question || '', derivedFrom: a.derivedFrom || null,
          values: (a.values || []).map(function (v) { return { id: v.id, label: v.label || v.id, status: v.status || '', note: v.note || '' }; }) };
      }),
      constraints: (ds.constraints || []).map(function (c) {
        var o = {}; ['id', 'level', 'if', 'require', 'msg', 'fix'].forEach(function (k) { if (k in c) o[k] = c[k]; }); return o;
      }),
      examples: (ds.examples || []).map(function (e) {
        return { id: e.id, label: e.label || e.id, path: e.path || '', status: e.status || '', blueprint: e.blueprint || '', asBuilt: e.asBuilt || {} };
      }),
      bricks: (ds.bricks || []).reduce(function (o, b) { o[b.id] = { name: b.name || b.id, status: b.status || '' }; return o; }, dict())
    };
  }

  // Inline data (dist/index.html) or, served from the repository, the JSON files themselves.
  PSS.load = function () {
    if (window.PSS_DEMO) return Promise.resolve(window.PSS_DEMO);
    return Promise.all([getJSON('data/tabs.json'), getJSON('data/addons.json')]).then(function (r) {
      var tabs = r[0], addons = r[1];
      var ids = tabs.filter(function (t) { return t.scenario; }).map(function (t) { return t.scenario; });
      return Promise.all([
        Promise.all(ids.map(function (id) { return getJSON('scenarios/' + id + '.json'); })),
        getJSON('../docs/design-guide/design-space.json').then(brickData, function () { return null; })
      ]).then(function (r2) {
        var scenarios = {};
        r2[0].forEach(function (s) { scenarios[s.id] = s; });
        return { tabs: tabs, addons: addons, scenarios: scenarios, bricks: r2[1] };
      });
    });
  };

  // ---------------------------------------------------------------- registry
  // Every id a text may reference or an arrow may end at: what it is, how it is named and
  // the DOM id of its home in the picture.
  PSS.domId = function (id) { return 'x-' + id; };

  var SECTION_LABEL = { code: 'contract code', long_lived: 'long-lived state', interaction: 'this interaction' };
  PSS.SECTION_LABEL = SECTION_LABEL;

  PSS.prepare = function (s) {
    if (s._reg) return s;
    var reg = dict(), fns = dict(), circuits = dict(), ents = dict(), madeAt = dict();
    function add(id, kind, label, extra) {
      var r = { id: id, kind: kind, label: label };
      if (extra) for (var k in extra) r[k] = extra[k];
      reg[id] = r;
      return r;
    }
    s.entities.forEach(function (e) {
      ents[e.id] = e;
      add(e.id, 'entity', e.label);
      ['code', 'long_lived', 'interaction'].forEach(function (sec) {
        add(e.id + '.' + sec, 'section', e.label + ': ' + SECTION_LABEL[sec], { entity: e.id });
      });
      (e.circuits || []).forEach(function (c) {
        circuits[c.id] = c;
        c._entity = e.id;
        add(c.id, 'circuit', c.id, { code: true });
        (c.logic || []).forEach(function (l, i) { if (l.id) add(l.id, 'logic', c.id + ', line ' + (i + 1), { owner: c.id }); });
        ['params', 'outputs'].forEach(function (k) { if (c[k]) add(c[k].id, 'cxitem', c[k].label, { owner: c.id }); });
      });
    });
    s.contracts.forEach(function (k) {
      add(k.id, 'contract', k.label);
      add(k.id + '.public', 'zone', k.label + ': public state', { contract: k.id });
      add(k.id + '.private', 'zone', k.label + ': private state', { contract: k.id });
      (k.functions || []).forEach(function (f) {
        fns[f.id] = f;
        f._contract = k.id;
        f._enqueuedBy = [];
        add(f.id, 'function', f.id, { code: true });
        (f.logic || []).forEach(function (l, i) { if (l.id) add(l.id, 'logic', f.id + ', line ' + (i + 1), { owner: f.id }); });
      });
    });
    s.contracts.forEach(function (k) {
      (k.functions || []).forEach(function (f) {
        (f.enqueues || []).forEach(function (q) { if (fns[q] && fns[q]._enqueuedBy.indexOf(f.id) < 0) fns[q]._enqueuedBy.push(f.id); });
      });
    });
    add('tx', 'tx', 'the transaction');
    (s.initial || []).forEach(function (eff) {
      if (eff.item) { add(eff.item.id, 'item', eff.item.label); madeAt[eff.item.id] = 0; }
    });
    // which functions ever run: a row that never runs in the scenario is drawn idle
    var ran = dict();
    s.steps.forEach(function (st, i) {
      (st.effects || []).forEach(function (eff) {
        if (eff.op === 'create' && eff.item) { add(eff.item.id, 'item', eff.item.label); madeAt[eff.item.id] = i + 1; }
      });
      (st.acts || []).forEach(function (a) { ran[a] = true; });
    });
    // names linked automatically wherever they stand in text as whole words: functions
    // and circuits with an underscore in their name
    var auto = Object.keys(fns).concat(Object.keys(circuits)).filter(function (n) { return n.indexOf('_') >= 0; });
    auto.sort(function (a, b) { return b.length - a.length; });
    s._reg = reg; s._fns = fns; s._circuits = circuits; s._ents = ents; s._madeAt = madeAt; s._ran = ran;
    s._auto = auto.length ? new RegExp('(^|[^A-Za-z0-9_\\[])(' + auto.map(escRe).join('|') + ')(?![A-Za-z0-9_])', 'g') : null;
    return s;
  };

  function escRe(x) { return x.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'); }

  // ---------------------------------------------------------------- text markup
  var ESC = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' };
  PSS.esc = function (x) { return String(x == null ? '' : x).replace(/[&<>"']/g, function (c) { return ESC[c]; }); };

  // `code` and [[id]] / [[id|text]] references; function and circuit names with an
  // underscore link by themselves. `live` says which items exist at the shown step.
  PSS.text = function (str, s, live) {
    if (str == null) return '';
    var html = PSS.esc(str);
    html = html.replace(/\[\[([^\]|]+)(?:\|([^\]]*))?\]\]/g, function (m, id, shown) {
      return PSS.refHtml(s, id, shown, live);
    });
    html = html.replace(/`([^`]+)`/g, '<code>$1</code>');
    if (s && s._auto) {
      // link bare names only outside tags and outside existing links
      var parts = html.split(/(<[^>]+>)/), inA = 0;
      for (var i = 0; i < parts.length; i++) {
        var p = parts[i];
        if (p.charAt(0) === '<') {
          if (/^<a[\s>]/.test(p)) inA++;
          else if (/^<\/a>/.test(p)) inA--;
          continue;
        }
        if (!inA) parts[i] = p.replace(s._auto, function (m, pre, name) { return pre + PSS.refHtml(s, name, null, live, true); });
      }
      html = parts.join('');
    }
    return html;
  };

  PSS.refHtml = function (s, id, shown, live, bare) {
    var r = s && s._reg[id];
    var label = shown != null && shown !== '' ? PSS.esc(shown) : PSS.esc(r ? r.label : id);
    if (r && r.code && (shown == null || shown === '') && !bare) label = '<code>' + label + '</code>';
    if (!r) return label;
    if (r.kind === 'item' && live && !live[id]) {
      var at = s._madeAt[id];
      return '<span class="ref-off" title="made at step ' + at + '">' + label + '</span>';
    }
    return '<a class="ref" href="#' + PSS.domId(id) + '" data-ref="' + PSS.esc(id) + '">' + label + '</a>';
  };

  PSS.plain = function (str) {
    return String(str || '').replace(/\[\[([^\]|]+)(?:\|([^\]]*))?\]\]/g, function (m, id, shown) { return shown || id; }).replace(/`/g, '');
  };

  // ---------------------------------------------------------------- replay
  function clone(x) { return JSON.parse(JSON.stringify(x)); }
  function placeKey(p) { return p.in + '|' + p.sec + (p.group ? '|' + p.group : ''); }
  PSS.placeKey = placeKey;

  // The state at step k (0: before step 1): every item made so far, where it sits, the step
  // that made it, the step that last changed it, whether it is spent, and this step's old
  // value of an updated item. Items keep the order they were made in.
  PSS.replay = function (s, k) {
    var items = dict(), order = [], seq = 0;
    function create(eff, n) {
      var it = { id: eff.item.id, item: clone(eff.item), place: eff.at, born: n, changed: null, spent: null, old: null, seq: seq++ };
      items[it.id] = it;
      order.push(it.id);
    }
    (s.initial || []).forEach(function (eff) { if (eff.op === 'create') create(eff, 0); });
    var lastRan = dict(), interaction = null;
    for (var n = 1; n <= k && n <= s.steps.length; n++) {
      var st = s.steps[n - 1];
      if (st.interaction) interaction = st.interaction;
      (st.effects || []).forEach(function (eff) {
        var it = items[eff.ref];
        switch (eff.op) {
          case 'create': create(eff, n); break;
          case 'update':
            if (!it) break;
            var before = it.item.value;
            for (var key in eff.set) it.item[key] = clone(eff.set[key]);
            it.changed = n;
            it.old = n === k && 'value' in eff.set && before !== eff.set.value ? before : null;
            if (n !== k) it.old = null;
            break;
          case 'spend': if (it) { it.spent = n; if (eff.note) it.spentNote = eff.note; } break;
          case 'move': if (it) { it.place = eff.to; it.moved = n; } break;
          case 'remove': if (it) { delete items[eff.ref]; } break;
        }
      });
      var callNo = 0;
      (st.acts || []).forEach(function (a) {
        var f = s._fns[a] || s._circuits[a];
        if (!f) return;
        lastRan[a] = { step: n, call: null };
      });
      (st.calls || []).forEach(function (c) {
        if (c.kind === 'private_to_public_enqueue' || c.kind === 'public_to_public') {
          callNo++;
          lastRan[c.callee] = { step: n, call: callNo };
        }
      });
    }
    // old values belong only to the shown step
    order.forEach(function (id) { var it = items[id]; if (it && it.changed !== k) it.old = null; });
    var byPlace = dict(), live = dict();
    order.forEach(function (id) {
      var it = items[id];
      if (!it) return;
      live[id] = true;
      var pk = placeKey(it.place);
      (byPlace[pk] = byPlace[pk] || []).push(it);
    });
    return { k: k, items: items, byPlace: byPlace, live: live, lastRan: lastRan, interaction: interaction };
  };

  // ---------------------------------------------------------------- the brick panel's rules
  function holds(cond, opts) {
    if (!cond) return true;
    if (cond.not) return !holds(cond.not, opts);
    for (var axis in cond) {
      if (cond[axis].indexOf(opts[axis]) < 0) return false;
    }
    return true;
  }
  // the constraints a set of options breaks: [{rule, level}]
  PSS.broken = function (constraints, opts) {
    return constraints.filter(function (c) { return holds(c.if, opts) && !holds(c.require, opts); });
  };
})();
