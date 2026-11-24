/* The view: renders a scenario at step k into the page, as HTML strings from the replayed
   state. Entities down the left, the flow lane, smart-contract land on the right, then the
   flow list, who learns what, the picked item and the brick panel. */
(function () {
  'use strict';
  var PSS = window.PSS;
  var esc = PSS.esc;

  var RD = { public: 'pub', user: 'usr', shared: 'shr', operator: 'opr' };
  var READER_TEXT = {
    public: 'anyone: it is on chain or published',
    user: 'one user only',
    shared: 'nobody alone: the nodes hold it as secret shares, any two together can open it',
    operator: 'the operator\'s side only: a node, the orchestrator or the relayer, not the chain'
  };
  var LK = { assert: 'a', flag: 'f', read: 'r', load: 'r', compute: 'c', write: 'e', push: 'e', emit: 'e', enqueue: 'e', seal: 'e', complete: 'e', store: 'e' };
  var CIRCLED = ['', '①', '②', '③', '④', '⑤', '⑥', '⑦', '⑧', '⑨'];

  function rd(r) { return RD[r] || 'pub'; }
  function mark(reader, form) {
    var base = 'm-' + rd(reader);
    var sym = base;
    if (form === 'sealed' && reader !== 'public') sym = base + '-s';
    if (reader === 'shared' && form !== 'sealed') sym = 'm-shr';
    return '<svg class="mk" aria-hidden="true"><use href="#' + sym + '"/></svg>';
  }
  PSS.mark = mark;

  // ------------------------------------------------------------------ items
  function T(ctx, x) { return PSS.text(x, ctx.s, ctx.live); }

  function bornBadge(it, ctx) {
    if (!it) return '';
    var n = it.changed != null ? it.changed : it.born;
    var title = 'made at step ' + it.born + (it.changed != null ? ', changed at step ' + it.changed : '') + (it.moved ? ', moved at step ' + it.moved : '') + (it.spent ? ', spent at step ' + it.spent : '');
    var text = it.changed != null && it.changed !== it.born ? it.born + '·' + it.changed : String(n);
    return '<span class="born" title="' + esc(title) + '">' + esc(text) + '</span>';
  }

  function perNode(x) {
    if (!x.per_node) return '';
    var keys = Object.keys(x.per_node);
    return '<div class="pn">' + keys.map(function (i) { return 'node ' + esc(i) + ': ' + esc(x.per_node[i]); }).join(' · ') + '</div>';
  }

  function fieldHtml(f, ctx) {
    var cls = 'f ' + (f.reader ? rd(f.reader) : '');
    var src = f.src ? '<span class="src">' + esc(f.src) + '</span>' : '';
    var note = f.note ? ' <em>' + T(ctx, f.note) + '</em>' : '';
    var mk = f.reader ? mark(f.reader, f.form) : '<span></span>';
    if (f.fields && f.fields.length) {
      return '<div class="st in ' + (f.reader ? rd(f.reader) : '') + '"><div class="sh"><b>' + esc(f.k) + ':' + (f.v ? ' ' + T(ctx, f.v) : '') + ' ' + esc(f.open || '{') + '</b>' + (f.note ? '<span class="meta">' + T(ctx, f.note) + '</span>' : '') + '</div>' +
        f.fields.map(function (g) { return fieldHtml(g, ctx); }).join('') +
        '<div class="to"><b>' + esc(f.close || '}') + '</b></div>' + perNode(f) + '</div>';
    }
    return '<div class="' + cls + '">' + mk + '<span class="k">' + esc(f.k) + ':</span><span class="val">' + src + T(ctx, f.v) + note + '</span></div>' + (f.per_node ? perNode(f) : '');
  }

  // an item at rest in a place (it: the replayed record) or a free struct (a call, a
  // proof's public inputs): `it` null
  function itemHtml(x, it, ctx, opts) {
    opts = opts || {};
    var cls = [], id = opts.noId ? '' : ' id="' + PSS.domId(x.id) + '"';
    var data = it ? ' data-item="' + esc(x.id) + '"' : '';
    if (it && (it.born === ctx.k || it.changed === ctx.k || it.moved === ctx.k)) cls.push('new');
    if (it && it.spent) cls.push('gone');
    if (it && ctx.pickedSame && (x.id === ctx.picked || (x.same && x.same === ctx.pickedSame))) cls.push('picked');
    var spentNote = it && it.spent ? ' <em>' + esc(it.spentNote || 'spent at step ' + it.spent) + '</em>' : '';
    if (x.fields && x.fields.length) {
      var to = '';
      if (x.to || x.close !== '') {
        to = '<div class="to ' + (x.to_reader ? rd(x.to_reader) : '') + '"><b>' + esc(x.close || '}') + '</b>' +
          (x.to_reader && x.to ? ' ' + mark(x.to_reader, x.to_form) : '') + (x.to ? ' <span>' + T(ctx, x.to) + '</span>' : '') + spentNote + '</div>';
      }
      return '<div class="st ' + cls.join(' ') + ' ' + rd(x.reader) + '"' + id + data + '>' +
        '<div class="sh"><b>' + T(ctx, x.label) + (x.value ? ' ' + T(ctx, x.value) : '') + ' ' + esc(x.open || '{') + '</b>' +
        (x.note ? '<span class="meta">' + T(ctx, x.note) + '</span>' : '') + (it ? bornBadge(it, ctx) : '') + '</div>' +
        x.fields.map(function (f) { return fieldHtml(f, ctx); }).join('') + to + perNode(x) + '</div>';
    }
    var val = '';
    if (it && it.old != null) val = ' <span class="v old">' + T(ctx, it.old) + '</span> → <span class="v">' + T(ctx, x.value) + '</span>';
    else if (x.value) val = ' <span class="v">' + T(ctx, x.value) + '</span>';
    return '<li class="it ' + rd(x.reader) + ' ' + cls.join(' ') + '"' + id + data + '>' + mark(x.reader, x.form) +
      '<span>' + T(ctx, x.label) + val + (x.note ? ' <em>' + T(ctx, x.note) + '</em>' : '') + spentNote + perNode(x) + '</span>' +
      (it ? bornBadge(it, ctx) : '<span></span>') + '</li>';
  }

  // a run of items: rows grouped in <ul>, structs between them
  function itemsHtml(list, ctx) {
    var out = '', rows = '';
    list.forEach(function (it) {
      var h = itemHtml(it.item, it, ctx);
      if (h.slice(0, 3) === '<li') rows += h;
      else { if (rows) { out += '<ul class="rows">' + rows + '</ul>'; rows = ''; } out += h; }
    });
    if (rows) out += '<ul class="rows">' + rows + '</ul>';
    return out;
  }

  // ------------------------------------------------------------------ logic lists
  function logicHtml(lines, ctx) {
    if (!lines || !lines.length) return '';
    return '<ol class="lg">' + lines.map(function (l) {
      var id = l.id ? ' id="' + PSS.domId(l.id) + '"' : '';
      var tail = '';
      if (l.msg) tail += ': "' + esc(l.msg) + '"';
      if (l.code) tail += ' <em>→ ' + esc(l.code) + '</em>';
      return '<li' + id + '><span class="lk ' + (LK[l.kind] || 'c') + '">' + esc(l.kind) + '</span><span>' + T(ctx, l.text) + tail + '</span></li>';
    }).join('') + '</ol>';
  }

  // ------------------------------------------------------------------ circuits (under Node i)
  function circuitHtml(c, ctx) {
    var on = ctx.acts[c.id];
    var open = on || ctx.open[c.id];
    var lr = ctx.state.lastRan[c.id];
    var born = lr ? '<span class="born">' + lr.step + '</span>' : '';
    var vk = c.vk_hash ? 'vk hash <span class="v">' + esc(c.vk_hash) + '</span>' : (c.vk_note ? T(ctx, c.vk_note) : '');
    var by = c.verified_by ? ' · verified by → ' + PSS.refHtml(ctx.s, c.verified_by, null, ctx.live) : '';
    var body = '';
    if (c.params) body += itemHtml(c.params, null, ctx, { noId: false });
    body += logicHtml(c.logic, ctx);
    if (c.total_note) body += '<div class="meta">' + T(ctx, c.total_note) + '</div>';
    if (c.outputs) body += itemHtml(c.outputs, null, ctx);
    return '<li class="fx' + (on ? ' on' : '') + (ctx.s._ran[c.id] ? '' : ' idle') + '" id="' + PSS.domId(c.id) + '"><details' + (open ? ' open' : '') + '>' +
      '<summary class="fsum"><span class="fh"><b class="nm">' + esc(c.id) + '</b><span class="kd">co-SNARK circuit</span>' + (c.total ? '<span class="kd">total</span>' : '') + born + '</span>' +
      '<span class="fs">' + T(ctx, c.summary) + '</span><span class="xr">' + vk + by + '</span></summary>' +
      '<div class="fb">' + body + '</div></details></li>';
  }

  // ------------------------------------------------------------------ entities (left)
  function sectionHtml(e, sec, ctx) {
    var sid = e.id + '.' + sec;
    var list = ctx.state.byPlace[e.id + '|' + sec] || [];
    var circuits = sec === 'code' ? (e.circuits || []) : [];
    var sn = '';
    if (sec === 'code' && circuits.length) sn = 'the circuits it runs (co-SNARK)';
    if (sec === 'interaction' && ctx.state.interaction && ctx.s.interactions) sn = ctx.s.interactions[ctx.state.interaction] || '';
    var open = ctx.secOpen[sid] != null ? ctx.secOpen[sid] : true;
    var inner = itemsHtml(list, ctx);
    if (circuits.length) inner += '<ul class="flist">' + circuits.map(function (c) { return circuitHtml(c, ctx); }).join('') + '</ul>';
    if (!list.length && !circuits.length) inner = '<div class="none">' + T(ctx, (e.empty && e.empty[sec]) || 'nothing yet') + '</div>';
    return '<details class="sec" id="' + PSS.domId(sid) + '" data-sec="' + esc(sid) + '"' + (open ? ' open' : '') + '><summary><span class="cap">' + esc(PSS.SECTION_LABEL[sec]) + '</span>' +
      (sn ? '<span class="sn">' + T(ctx, sn) + '</span>' : '') + '</summary><div class="rows">' + inner + '</div></details>';
  }

  function entityHtml(e, ctx) {
    var lit = ctx.acts[e.id];
    var who = '<div class="who"><b>' + esc(e.label) + '</b>' + (e.copies ? '<span class="x3">×' + e.copies + ' · i = 0, 1, 2</span>' : '') +
      (e.role ? '<span>' + T(ctx, e.role) + '</span>' : '') + '</div>';
    if (e.idle) {
      return '<div class="ent off" id="' + PSS.domId(e.id) + '">' + who + '<div class="none">' + T(ctx, e.idle) + '</div></div>';
    }
    return '<div class="ent' + (lit ? ' lit' : '') + '" id="' + PSS.domId(e.id) + '">' + who +
      (e.meta ? '<div class="meta">' + T(ctx, e.meta) + '</div>' : '') +
      ['code', 'long_lived', 'interaction'].map(function (sec) { return sectionHtml(e, sec, ctx); }).join('') + '</div>';
  }

  function entitiesHtml(ctx) {
    // one band per entity; consecutive users share one
    var bands = [], users = [];
    function flush() { if (users.length) { bands.push('<div class="band">' + users.join('') + '</div>'); users = []; } }
    ctx.s.entities.forEach(function (e) {
      if (e.kind === 'user') { users.push(entityHtml(e, ctx)); return; }
      flush();
      bands.push('<div class="band">' + entityHtml(e, ctx) + '</div>');
    });
    flush();
    return '<div><div class="sideh"><b>Who holds what</b><span>each entity\'s database: contract code, long-lived state, this interaction</span></div>' +
      '<div class="ents">' + bands.join('') + '</div></div>';
  }

  // ------------------------------------------------------------------ contracts (right)
  function verLine(f, ctx, on) {
    if (f.verifies) {
      var v = f.verifies;
      return '<span class="ver' + (on ? '' : ' dim') + '"><b>verifies co-SNARK proof: ' + PSS.refHtml(ctx.s, v.circuit, null, ctx.live) + ' vk</b> (' + T(ctx, v.vk_source) + ')' +
        (v.signatures ? ' · ' + T(ctx, v.signatures) : '') + '</span>';
    }
    if (f.check) return '<span class="ver dim">' + T(ctx, f.check) + '</span>';
    return '';
  }

  function fnHtml(f, ctx) {
    var st = ctx.step;
    var on = ctx.acts[f.id];
    var lr = ctx.state.lastRan[f.id];
    var born = lr ? '<span class="born">' + lr.step + (lr.call ? ' · ' + (CIRCLED[lr.call] || lr.call) : '') + '</span>' : '';
    var calledNow = PSS.dict();
    (st && st.calls || []).forEach(function (c) { calledNow[c.caller + '>' + c.callee] = true; });
    var links = '';
    if (f.enqueues && f.enqueues.length) {
      var n = 0;
      links = 'enqueues → ' + f.enqueues.map(function (q) {
        var now = on && calledNow[f.id + '>' + q];
        var label = (now ? (CIRCLED[callIndex(st, f.id, q)] || '') + ' ' : '') + q;
        return '<a class="ref' + (now ? ' now' : '') + '" href="#' + PSS.domId(q) + '" data-ref="' + esc(q) + '">' + esc(label.trim()) + '</a>';
      }).join(', ');
    } else if (f._enqueuedBy && f._enqueuedBy.length) {
      links = 'enqueued by ← ' + f._enqueuedBy.map(function (q) {
        var now = on && calledNow[q + '>' + f.id];
        return '<a class="ref' + (now ? ' now' : '') + '" href="#' + PSS.domId(q) + '" data-ref="' + esc(q) + '">' + esc(q) + '</a>';
      }).join(', ');
    } else if (f.called) links = T(ctx, f.called);
    var kinds = '<span class="kd">' + esc(f.kind) + '</span>' + (f.badges || []).map(function (b) { return '<span class="kd">' + esc(b) + '</span>'; }).join('');
    var runsIn = on && f.runs_in ? '<span class="meta">' + T(ctx, f.runs_in) + '</span>' : '';
    var ver = verLine(f, ctx, on);
    var head = '<span class="fh"><b class="nm">' + esc(f.id) + '</b>' + kinds + runsIn + born + '</span>' +
      (ver || '<span class="fs">' + T(ctx, f.summary) + '</span>') + (links ? '<span class="xr">' + links + '</span>' : '');
    var body = '';
    if (ver && f.summary) body += '<div class="meta">' + T(ctx, f.summary) + '</div>';
    if (on && st) {
      if (st.tx && st.tx.entry === f.id && st.tx.args) body += itemHtml(st.tx.args, null, ctx);
      (st.calls || []).forEach(function (c) { if (c.callee === f.id && c.args) body += itemHtml(c.args, null, ctx); });
      (st.verifies || []).forEach(function (v) { if (v.function === f.id && v.public_inputs) body += itemHtml(v.public_inputs, null, ctx); });
    }
    body += logicHtml(f.logic, ctx);
    var cls = 'fx' + (on ? ' on' : '') + (f.kind === 'utility' ? ' util' : '') + (!ctx.s._ran[f.id] ? ' idle' : '');
    if (!body) return '<li class="' + cls + '" id="' + PSS.domId(f.id) + '"><div class="fsum">' + head + '</div></li>';
    var open = on || ctx.open[f.id];
    return '<li class="' + cls + '" id="' + PSS.domId(f.id) + '"><details' + (open ? ' open' : '') + '><summary class="fsum">' + head + '</summary><div class="fb">' + body + '</div></details></li>';
  }

  function callIndex(st, caller, callee) {
    var n = 0, found = 0;
    (st.calls || []).forEach(function (c) {
      if (c.kind === 'private_to_public_enqueue' || c.kind === 'public_to_public') { n++; if (c.caller === caller && c.callee === callee && !found) found = n; }
    });
    return found;
  }

  function txHtml(st, ctx) {
    var tx = st.tx;
    return '<li class="txo" id="' + PSS.domId('tx') + '"><header><b>Transaction ' + esc(tx.id) + '</b><span>submitted by ' + PSS.refHtml(ctx.s, tx.by, null, ctx.live) +
      ' · step ' + st.n + ' · enters ↓ ' + PSS.refHtml(ctx.s, tx.entry, null, ctx.live) + '</span></header>' + (tx.item ? itemHtml(tx.item, null, ctx, { noId: true }) : '') + '</li>';
  }

  // running functions first, in the order the step names them; the rest in fixed order
  function ordered(list, ctx) {
    var acts = (ctx.step && ctx.step.acts) || [];
    var on = list.filter(function (f) { return ctx.acts[f.id]; });
    on.sort(function (a, b) { return acts.indexOf(a.id) - acts.indexOf(b.id); });
    return on.concat(list.filter(function (f) { return !ctx.acts[f.id]; }));
  }

  function fnGroupHtml(k, side, ctx) {
    var list = (k.functions || []).filter(function (f) { return side === 'public' ? (f.kind === 'public' || f.kind === 'view') : (f.kind === 'private' || f.kind === 'utility'); });
    var cap = side === 'public' ? 'Public functions · everyone sees their calls and arguments' : 'Private functions · they run in the sender\'s wallet' + (list.some(function (f) { return f.enqueues && f.enqueues.length; }) ? ' and enqueue public calls' : '');
    if (!list.length) return '<div class="fns"><div class="cap">' + esc(cap.split(' · ')[0]) + '</div><div class="none">none</div></div>';
    var st = ctx.step, rows = '';
    ordered(list, ctx).forEach(function (f) {
      if (st && st.tx && st.tx.entry === f.id) rows += txHtml(st, ctx);
      rows += fnHtml(f, ctx);
    });
    return '<div class="fns"><div class="cap">' + esc(cap) + '</div><ul class="flist">' + rows + '</ul></div>';
  }

  function stateHalfHtml(k, side, ctx) {
    var groups = (k.groups && k.groups[side]) || [];
    var cap = side === 'public' ? 'Public state · everyone can read it' : 'Private state · what private functions emitted; the chain holds hashes and ciphertexts';
    var inner = '';
    groups.forEach(function (g) {
      var list = ctx.state.byPlace[k.id + '|' + side + '|' + g.id] || [];
      inner += '<div class="sub">' + T(ctx, g.label) + '</div>' + (list.length ? itemsHtml(list, ctx) : '<div class="none">nothing yet</div>');
    });
    if (!groups.length) inner = '<div class="none">' + T(ctx, (k.empty && k.empty[side]) || 'none') + '</div>';
    return '<div class="half" id="' + PSS.domId(k.id + '.' + side) + '"><div class="cap">' + esc(cap) + '</div>' + inner + '</div>';
  }

  function contractHtml(k, ctx) {
    return '<div class="kbox" id="' + PSS.domId(k.id) + '"><header><b>' + esc(k.label) + '</b>' + (k.address ? '<span class="v">' + esc(k.address) + '</span>' : '') + '</header>' +
      stateHalfHtml(k, 'public', ctx) + fnGroupHtml(k, 'public', ctx) +
      '<div class="divide"><span>public ↑ · private ↓' + (k.functions.some(function (f) { return f.kind === 'public'; }) ? '' : ' · nothing crosses') + '</span></div>' +
      stateHalfHtml(k, 'private', ctx) + fnGroupHtml(k, 'private', ctx) + '</div>';
  }

  // ------------------------------------------------------------------ the timeline and the banner
  function timelineHtml(ctx) {
    var s = ctx.s, k = ctx.k;
    var html = s.phases.map(function (p) {
      var dots = s.steps.map(function (st) {
        if (st.phase !== p.id) return '';
        var cls = 'd' + (st.tx ? ' t' : '') + (st.n < k ? ' done' : '') + (st.n === k ? ' now' : '');
        return '<button type="button" class="' + cls + '" data-step="' + st.n + '" title="' + esc(st.n + '. ' + PSS.plain(st.title)) + '" aria-label="step ' + st.n + '">' + (st.n === k ? st.n : '') + '</button>';
      }).join('');
      return '<div class="ph"><span class="cap">' + esc(p.label) + '</span><span class="dots">' + dots + '</span></div>';
    }).join('');
    var N = s.steps.length;
    return '<div class="tl" aria-label="Timeline">' + html + '<div class="ctl"><span>square = a transaction: its whole call chain lights up</span>' +
      '<button type="button" class="btn" data-go="prev"' + (k <= 1 ? ' disabled' : '') + '>← Prev</button>' +
      '<button type="button" class="btn' + (ctx.playing ? ' on' : '') + '" data-go="play" aria-pressed="' + (ctx.playing ? 'true' : 'false') + '">' + (ctx.playing ? 'Pause' : 'Play') + '</button>' +
      '<button type="button" class="btn" data-go="next"' + (k >= N ? ' disabled' : '') + '>Next →</button>' +
      '<span class="stepof">' + k + ' / ' + N + '</span></div></div>';
  }

  function bannerHtml(ctx) {
    var st = ctx.step;
    var basis = st.basis || ctx.s.basis || 'hand-written';
    var meta = [];
    if (st.interaction && ctx.s.interactions) meta.push('interaction: ' + T(ctx, ctx.s.interactions[st.interaction]));
    if (st.tx) meta.push('one transaction: ' + esc(st.tx.id));
    var ph = ctx.s.phases.filter(function (p) { return p.id === st.phase; })[0];
    if (ph) meta.unshift(esc(ph.label));
    return '<div class="step" aria-live="polite"><h2><span class="n">' + st.n + '</span>' + T(ctx, st.title) + '<span class="badge" title="hand-written: values are illustrative; recording steps from real runs comes later">' + esc(basis) + ' step</span></h2>' +
      '<p>' + T(ctx, st.text) + '</p><div class="meta2">' + meta.join('<span>·</span>') + '</div></div>';
  }

  function keyHtml() {
    return '<div class="key" aria-label="Key: who can read a value">' +
      '<span class="pub">' + mark('public') + 'public: anyone can read it</span>' +
      '<span class="usr">' + mark('user') + 'one user only</span>' +
      '<span class="shr">' + mark('shared', 'part') + 'secret-shared: one node\'s parts; no single node can read the value, two together can</span>' +
      '<span class="opr">' + mark('operator') + 'the operator\'s side only: a node, the orchestrator or the relayer reads it, the chain does not show it</span>' +
      '<span class="usr">' + mark('user', 'sealed') + '<span class="shr" style="display:inline-flex">' + mark('shared', 'sealed') + '</span>hollow mark: a hash, commitment or ciphertext of such a value</span>' +
      '<span><span class="born">9</span>made at step 9 (0: there before the play starts)</span>' +
      '<span><span class="it pub new" style="display:inline-block;padding:0 8px;border-left-width:3px">new</span>made or changed in this step</span>' +
      '<span><span class="lk a">assert</span>fails the transaction (or the proof) if false</span>' +
      '<span><span class="lk e">effect</span>writes, emits, pushes or enqueues</span>' +
      '<span><span class="lk r">read</span><span class="lk c">compute</span>reads state, computes a value</span>' +
      '<span><span class="lk f">flag</span>a total circuit\'s check: sets an error code, the proof still holds</span>' +
      '<span><a class="ref" href="#" onclick="return false">names</a> are links: a click opens and shows the thing named</span></div>';
  }

  // ------------------------------------------------------------------ lower panels
  function flowListHtml(ctx) {
    var fl = ctx.step.flows || [];
    if (!fl.length) return '<div class="pan flows-pan"><h2>Data flows in this step</h2><p>None: nothing moves between places in this step.</p></div>';
    return '<div class="pan flows-pan"><h2>Data flows in this step</h2><p>On a wide screen these are arrows between the items; hover one to read its line. Colour = who can read what travels.</p>' +
      '<ol class="flows" id="flowlist">' + fl.map(function (f, i) {
        return '<li class="' + rd(f.reader) + '"><span class="fn-n">' + (i + 1) + '</span><span class="fk">' + esc(f.kind) + '</span><span>' + T(ctx, f.text) + '</span></li>';
      }).join('') + '</ol></div>';
  }

  function learnsHtml(ctx) {
    var l = ctx.step.learns || [];
    return '<div class="pan"><h2>Who learns what in this step</h2>' + (l.length ? '<dl class="kv learn">' + l.map(function (x) {
      return '<dt>' + T(ctx, x.party) + '</dt><dd>' + T(ctx, x.text) + '</dd>';
    }).join('') + '</dl>' : '<p>Nobody learns anything new.</p>') + '</div>';
  }

  function placeText(p, ctx) {
    var s = ctx.s;
    if (s._ents[p.in]) return PSS.refHtml(s, p.in + '.' + p.sec, null, ctx.live);
    var k = s.contracts.filter(function (c) { return c.id === p.in; })[0];
    if (!k) return esc(p.in);
    var g = ((k.groups || {})[p.sec] || []).filter(function (x) { return x.id === p.group; })[0];
    return PSS.refHtml(s, k.id + '.' + p.sec, k.label + ', ' + p.sec + ' state', ctx.live) + (g ? ' (' + T(ctx, g.label) + ')' : '');
  }

  function pickedHtml(ctx) {
    var id = ctx.picked;
    var it = id && ctx.state.items[id];
    if (!it) return '<div class="pan"><h2>Picked item</h2><p>Click any item in the picture to see what it is, who can read it and where it is held.</p></div>';
    var x = it.item;
    var copies = [];
    Object.keys(ctx.state.items).forEach(function (oid) {
      var o = ctx.state.items[oid];
      if (oid === id || (x.same && o.item.same === x.same)) copies.push(o);
    });
    var made = ctx.s.steps[it.born - 1];
    return '<div class="pan" id="picked"><h2>Picked item: ' + T(ctx, x.label) + (x.value ? ' <span class="v">' + T(ctx, x.value) + '</span>' : '') + '</h2><dl class="kv">' +
      (x.about ? '<dt>What it is</dt><dd>' + T(ctx, x.about) + '</dd>' : '') +
      '<dt>Readable by</dt><dd class="' + rd(x.reader) + '">' + mark(x.reader, x.form) + ' ' + esc(READER_TEXT[x.reader] || x.reader) + (x.form === 'sealed' ? '; here only as a hash, commitment or ciphertext' : '') + '</dd>' +
      '<dt>Made</dt><dd>' + (it.born === 0 ? 'before the play starts' : 'at step ' + it.born + ': ' + T(ctx, made.title)) + (it.changed ? '; changed at step ' + it.changed : '') + (it.spent ? '; spent at step ' + it.spent : '') + '</dd>' +
      '<dt>Held at</dt><dd>' + copies.map(function (o) { return PSS.refHtml(ctx.s, o.id, o.item.label + (o.item.value ? ' ' + PSS.plain(o.item.value) : ''), ctx.live) + ' in ' + placeText(o.place, ctx); }).join('; ') + '</dd>' +
      '</dl></div>';
  }

  // ------------------------------------------------------------------ the brick panel
  // A status's look (design-space.json `statuses`): built and kept options plain; experimental
  // and external plain with their label; to-build and deferred dashed, not built yet;
  // not-offered struck through, refused whatever else is picked.
  var STATUS_CLASS = { 'to-build': 'hyp', deferred: 'hyp', 'not-offered': 'no' };
  function statusMark(b, status) {
    if (!status || status === 'built' || status === 'option') return { cls: '', small: '' };
    return { cls: STATUS_CLASS[status] ? ' ' + STATUS_CLASS[status] : '', small: b.statuses[status] || status };
  }

  function bricksHtml(ctx, data) {
    var b = data.bricks;
    var s = ctx.s;
    if (!b) return '<div class="pan"><h2>Bricks</h2><p>The design space did not load (serve the repository root, or build dist/index.html).</p></div>';
    var ex = b.examples.filter(function (e) { return e.id === s.example; })[0];
    var opts = ex ? ex.asBuilt : {};
    var use = PSS.dict();
    (ctx.step.bricks || []).forEach(function (a) { use[a] = true; });
    var rows = b.axes.map(function (a) {
      var chips = a.values.map(function (v) {
        var cls = 'op', small = '', title = v.note || '';
        if (opts[a.id] === v.id) {
          cls += ' act' + (use[a.id] ? ' use' : '');
        } else if (a.derivedFrom) {
          cls += ' dis';
          small = 'follows from ' + a.derivedFrom;
        } else {
          var o = {}; for (var key in opts) o[key] = opts[key];
          o[a.id] = v.id;
          var broken = PSS.broken(b.constraints, o);
          var errs = broken.filter(function (c) { return c.level === 'error'; });
          var warns = broken.filter(function (c) { return c.level !== 'error'; });
          if (errs.length) {
            cls += ' no';
            var fix = errs[0].fix ? Object.keys(errs[0].fix).map(function (fk) { return fk + ' ' + errs[0].fix[fk]; }).join(', ') : '';
            small = fix ? 'needs ' + fix : 'ruled out';
            title = errs.map(function (c) { return c.msg; }).join(' ');
          } else if (warns.length) {
            small = 'caution';
            title = warns.map(function (c) { return c.msg; }).join(' ');
          }
        }
        var st = statusMark(b, v.status);
        if (st.small) {
          if (st.cls && (' ' + cls + ' ').indexOf(st.cls + ' ') < 0) cls += st.cls;
          small = st.small + (small ? ' · ' + small : '');
        }
        return '<span class="' + cls + '"' + (title ? ' title="' + esc(title) + '"' : '') + '>' + esc(v.label) + (small ? '<small>' + esc(small) + '</small>' : '') + '</span>';
      }).join('');
      return '<dt>' + esc(a.label) + (a.derivedFrom ? '<small>follows from ' + esc(a.derivedFrom) + '</small>' : '') + '</dt><dd>' + chips + '</dd>';
    }).join('');
    var add = data.addons;
    if (add && b.bricks) {
      var mine = s.addons || [];
      rows += '<dt>' + esc(add.label) + '<small>beside the axes</small></dt><dd>' + (add.bricks || []).map(function (id) {
        var br = b.bricks[id] || { name: id, status: '' };
        var st = statusMark(b, br.status);
        var cls = 'op' + (mine.indexOf(id) >= 0 ? ' act' : '') + st.cls;
        return '<span class="' + cls + '" title="design-space.json brick ' + esc(id) + '">' + esc(br.name) + (st.small ? '<small>' + esc(st.small) + '</small>' : '') + '</span>';
      }).join('') + '</dd>';
    }
    return '<div class="pan" id="bricks"><h2>Bricks: every axis, this example\'s choice lit</h2>' +
      '<p>One row per axis of <code>design-space.json</code>. The example\'s option is outlined; violet where this step uses it. Every other option is shown with what rules it out for this example (hover for the rule).</p>' +
      '<div class="mini"><span class="op act use">at work in this step</span><span class="op act">chosen</span><span class="op">can be picked</span><span class="op hyp">not built yet<small>status</small></span><span class="op no">ruled out by another choice, or not offered</span><span class="op dis">follows from another axis</span></div>' +
      '<dl class="axes">' + rows + '</dl>' +
      '<div class="status"><b>This play: ' + esc(ex ? ex.label : s.label) + ' as built</b><span>' + esc(s.basis || 'hand-written') + ' steps, values illustrative</span>' +
      '<button type="button" class="btn" disabled title="coming next">Play another combination: coming next</button></div></div>';
  }

  // ------------------------------------------------------------------ the whole page at step k
  PSS.render = function (root, data, view) {
    var s = PSS.prepare(data.scenarios[view.tab]);
    var k = view.k;
    var state = PSS.replay(s, k);
    var step = s.steps[k - 1];
    var acts = PSS.dict(), open = PSS.dict();
    (step.acts || []).forEach(function (a) { acts[a] = true; });
    (step.open || []).forEach(function (a) { open[a] = true; });
    var picked = view.picked && state.items[view.picked] ? view.picked : (step.pick && state.items[step.pick] ? step.pick : null);
    var ctx = {
      s: s, k: k, step: step, state: state, live: state.live, acts: acts, open: open,
      secOpen: view.secOpen || PSS.dict(), playing: view.playing,
      picked: picked, pickedSame: picked ? (state.items[picked].item.same || picked) : null
    };
    root.innerHTML =
      timelineHtml(ctx) + bannerHtml(ctx) + flowListHtml(ctx) + keyHtml() +
      '<div class="stage" id="stage"><svg id="ov" aria-hidden="true"></svg>' + entitiesHtml(ctx) +
      '<div class="lane" id="lane" aria-hidden="true"><span class="cap">flows</span></div>' +
      '<div><div class="sideh"><b>Smart-contract land</b><span>Aztec · the only public/private divide</span></div><div class="kland">' +
      s.contracts.map(function (c) { return contractHtml(c, ctx); }).join('') + '</div></div></div>' +
      '<div class="low">' + learnsHtml(ctx) + pickedHtml(ctx) + '</div>' +
      bricksHtml(ctx, data);
    return ctx;
  };

  PSS.renderNext = function (root, tab) {
    root.innerHTML = '<div class="pan next-pan"><h2>' + esc(tab.label) + ' <span class="badge">coming next</span></h2>' +
      '<p>' + esc(tab.next || '') + '</p><p>This example\'s steps are the next phase of the demo. The ' + esc(tab.path) + ' path is drawn on the same diagram as the other examples.</p></div>';
  };
})();
