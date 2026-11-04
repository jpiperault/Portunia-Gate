var __defProp = Object.defineProperty;
var __typeError = (msg) => {
  throw TypeError(msg);
};
var __defNormalProp = (obj, key, value) => key in obj ? __defProp(obj, key, { enumerable: true, configurable: true, writable: true, value }) : obj[key] = value;
var __publicField = (obj, key, value) => __defNormalProp(obj, typeof key !== "symbol" ? key + "" : key, value);
var __accessCheck = (obj, member, msg) => member.has(obj) || __typeError("Cannot " + msg);
var __privateGet = (obj, member, getter) => (__accessCheck(obj, member, "read from private field"), getter ? getter.call(obj) : member.get(obj));
var __privateAdd = (obj, member, value) => member.has(obj) ? __typeError("Cannot add the same private member more than once") : member instanceof WeakSet ? member.add(obj) : member.set(obj, value);
var __privateSet = (obj, member, value, setter) => (__accessCheck(obj, member, "write to private field"), setter ? setter.call(obj, value) : member.set(obj, value), value);
var _t2, _e2, _a, _b;
typeof window < "u" && (window.__svelte || (window.__svelte = { v: /* @__PURE__ */ new Set() })).v.add("5");
const cr = 2, dr = "[", fr = "]", Je = {}, V = Symbol(), si = false, J = 2, gi = 4, St = 8, Yt = 16, ye = 32, Ue = 64, pt = 128, G = 256, vt = 512, j = 1024, Ce = 2048, Be = 4096, wt = 8192, Dt = 16384, hr = 32768, br = 65536, pr = 1 << 19, _i = 1 << 20, ct = Symbol("$state"), vr = Symbol("legacy props");
var xi = Array.isArray, wr = Array.prototype.indexOf, mr = Array.from, mt = Object.keys, gt = Object.defineProperty, Ne = Object.getOwnPropertyDescriptor, gr = Object.getOwnPropertyDescriptors, _r = Object.prototype, xr = Array.prototype, yi = Object.getPrototypeOf;
const dt = () => {
};
function Ci(t) {
  for (var e = 0; e < t.length; e++)
    t[e]();
}
let tt = [], It = [];
function Ei() {
  var t = tt;
  tt = [], Ci(t);
}
function yr() {
  var t = It;
  It = [], Ci(t);
}
function Xt(t) {
  tt.length === 0 && queueMicrotask(Ei), tt.push(t);
}
function oi() {
  tt.length > 0 && Ei(), It.length > 0 && yr();
}
function ki(t) {
  return t === this.v;
}
function Si(t, e) {
  return t != t ? e == e : t !== e || t !== null && typeof t == "object" || typeof t == "function";
}
function Cr(t) {
  return !Si(t, this.v);
}
function Er(t) {
  throw new Error("https://svelte.dev/e/effect_in_teardown");
}
function kr() {
  throw new Error("https://svelte.dev/e/effect_in_unowned_derived");
}
function Sr(t) {
  throw new Error("https://svelte.dev/e/effect_orphan");
}
function Dr() {
  throw new Error("https://svelte.dev/e/effect_update_depth_exceeded");
}
function Tr() {
  throw new Error("https://svelte.dev/e/hydration_failed");
}
function Rr() {
  throw new Error("https://svelte.dev/e/state_descriptors_fixed");
}
function $r() {
  throw new Error("https://svelte.dev/e/state_prototype_fixed");
}
function Ar() {
  throw new Error("https://svelte.dev/e/state_unsafe_local_read");
}
function Or() {
  throw new Error("https://svelte.dev/e/state_unsafe_mutation");
}
let Lr = false;
function ne(t, e) {
  var i = {
    f: 0,
    // TODO ideally we could skip this altogether, but it causes type errors
    v: t,
    reactions: null,
    equals: ki,
    rv: 0,
    wv: 0
  };
  return i;
}
function Pt(t) {
  return /* @__PURE__ */ Mr(ne(t));
}
// @__NO_SIDE_EFFECTS__
function Di(t, e = false) {
  const i = ne(t);
  return e || (i.equals = Cr), i;
}
// @__NO_SIDE_EFFECTS__
function Mr(t) {
  return k !== null && !Q && (k.f & J) !== 0 && (se === null ? Br([t]) : se.push(t)), t;
}
function H(t, e) {
  return k !== null && !Q && Xi() && (k.f & (J | Yt)) !== 0 && // If the source was created locally within the current derived, then
  // we allow the mutation.
  (se === null || !se.includes(t)) && Or(), Pr(t, e);
}
function Pr(t, e) {
  return t.equals(e) || (t.v, t.v = e, t.wv = Ui(), Ti(t, Ce), T !== null && (T.f & j) !== 0 && (T.f & (ye | Ue)) === 0 && (le === null ? zr([t]) : le.push(t))), e;
}
function Ti(t, e) {
  var i = t.reactions;
  if (i !== null)
    for (var r = i.length, n = 0; n < r; n++) {
      var o = i[n], c = o.f;
      (c & Ce) === 0 && (ce(o, e), (c & (j | G)) !== 0 && ((c & J) !== 0 ? Ti(
        /** @type {Derived} */
        o,
        Be
      ) : ei(
        /** @type {Effect} */
        o
      )));
    }
}
// @__NO_SIDE_EFFECTS__
function Ri(t) {
  var e = J | Ce, i = k !== null && (k.f & J) !== 0 ? (
    /** @type {Derived} */
    k
  ) : null;
  return T === null || i !== null && (i.f & G) !== 0 ? e |= G : T.f |= _i, {
    ctx: B,
    deps: null,
    effects: null,
    equals: ki,
    f: e,
    fn: t,
    reactions: null,
    rv: 0,
    v: (
      /** @type {V} */
      null
    ),
    wv: 0,
    parent: i ?? T
  };
}
function $i(t) {
  var e = t.effects;
  if (e !== null) {
    t.effects = null;
    for (var i = 0; i < e.length; i += 1)
      xe(
        /** @type {Effect} */
        e[i]
      );
  }
}
function Fr(t) {
  for (var e = t.parent; e !== null; ) {
    if ((e.f & J) === 0)
      return (
        /** @type {Effect} */
        e
      );
    e = e.parent;
  }
  return null;
}
function Nr(t) {
  var e, i = T;
  _e(Fr(t));
  try {
    $i(t), e = zi(t);
  } finally {
    _e(i);
  }
  return e;
}
function Ai(t) {
  var e = Nr(t), i = (me || (t.f & G) !== 0) && t.deps !== null ? Be : j;
  ce(t, i), t.equals(e) || (t.v = e, t.wv = Ui());
}
function Zt(t) {
  console.warn("https://svelte.dev/e/hydration_mismatch");
}
let ee = false;
function at(t) {
  ee = t;
}
let z;
function _t(t) {
  if (t === null)
    throw Zt(), Je;
  return z = t;
}
function Oi() {
  return _t(
    /** @type {TemplateNode} */
    /* @__PURE__ */ Tt(z)
  );
}
function Ft(t) {
  if (ee) {
    if (/* @__PURE__ */ Tt(z) !== null)
      throw Zt(), Je;
    z = t;
  }
}
function ke(t, e = null, i) {
  if (typeof t != "object" || t === null || ct in t)
    return t;
  const r = yi(t);
  if (r !== _r && r !== xr)
    return t;
  var n = /* @__PURE__ */ new Map(), o = xi(t), c = ne(0);
  o && n.set("length", ne(
    /** @type {any[]} */
    t.length
  ));
  var f;
  return new Proxy(
    /** @type {any} */
    t,
    {
      defineProperty(h, d, p) {
        (!("value" in p) || p.configurable === false || p.enumerable === false || p.writable === false) && Rr();
        var w = n.get(d);
        return w === void 0 ? (w = ne(p.value), n.set(d, w)) : H(w, ke(p.value, f)), true;
      },
      deleteProperty(h, d) {
        var p = n.get(d);
        if (p === void 0)
          d in h && n.set(d, ne(V));
        else {
          if (o && typeof d == "string") {
            var w = (
              /** @type {Source<number>} */
              n.get("length")
            ), s = Number(d);
            Number.isInteger(s) && s < w.v && H(w, s);
          }
          H(p, V), ai(c);
        }
        return true;
      },
      get(h, d, p) {
        var _a2;
        if (d === ct)
          return t;
        var w = n.get(d), s = d in h;
        if (w === void 0 && (!s || ((_a2 = Ne(h, d)) == null ? void 0 : _a2.writable)) && (w = ne(ke(s ? h[d] : V, f)), n.set(d, w)), w !== void 0) {
          var a = U(w);
          return a === V ? void 0 : a;
        }
        return Reflect.get(h, d, p);
      },
      getOwnPropertyDescriptor(h, d) {
        var p = Reflect.getOwnPropertyDescriptor(h, d);
        if (p && "value" in p) {
          var w = n.get(d);
          w && (p.value = U(w));
        } else if (p === void 0) {
          var s = n.get(d), a = s == null ? void 0 : s.v;
          if (s !== void 0 && a !== V)
            return {
              enumerable: true,
              configurable: true,
              value: a,
              writable: true
            };
        }
        return p;
      },
      has(h, d) {
        var _a2;
        if (d === ct)
          return true;
        var p = n.get(d), w = p !== void 0 && p.v !== V || Reflect.has(h, d);
        if (p !== void 0 || T !== null && (!w || ((_a2 = Ne(h, d)) == null ? void 0 : _a2.writable))) {
          p === void 0 && (p = ne(w ? ke(h[d], f) : V), n.set(d, p));
          var s = U(p);
          if (s === V)
            return false;
        }
        return w;
      },
      set(h, d, p, w) {
        var _a2;
        var s = n.get(d), a = d in h;
        if (o && d === "length")
          for (var l = p; l < /** @type {Source<number>} */
          s.v; l += 1) {
            var u = n.get(l + "");
            u !== void 0 ? H(u, V) : l in h && (u = ne(V), n.set(l + "", u));
          }
        s === void 0 ? (!a || ((_a2 = Ne(h, d)) == null ? void 0 : _a2.writable)) && (s = ne(void 0), H(s, ke(p, f)), n.set(d, s)) : (a = s.v !== V, H(s, ke(p, f)));
        var b = Reflect.getOwnPropertyDescriptor(h, d);
        if ((b == null ? void 0 : b.set) && b.set.call(w, p), !a) {
          if (o && typeof d == "string") {
            var $ = (
              /** @type {Source<number>} */
              n.get("length")
            ), P = Number(d);
            Number.isInteger(P) && P >= $.v && H($, P + 1);
          }
          ai(c);
        }
        return true;
      },
      ownKeys(h) {
        U(c);
        var d = Reflect.ownKeys(h).filter((s) => {
          var a = n.get(s);
          return a === void 0 || a.v !== V;
        });
        for (var [p, w] of n)
          w.v !== V && !(p in h) && d.push(p);
        return d;
      },
      setPrototypeOf() {
        $r();
      }
    }
  );
}
function ai(t, e = 1) {
  H(t, t.v + e);
}
var li, Li, Mi, Pi;
function Wt() {
  if (li === void 0) {
    li = window, Li = /Firefox/.test(navigator.userAgent);
    var t = Element.prototype, e = Node.prototype;
    Mi = Ne(e, "firstChild").get, Pi = Ne(e, "nextSibling").get, t.__click = void 0, t.__className = void 0, t.__attributes = null, t.__styles = null, t.__e = void 0, Text.prototype.__t = void 0;
  }
}
function Fi(t = "") {
  return document.createTextNode(t);
}
// @__NO_SIDE_EFFECTS__
function xt(t) {
  return Mi.call(t);
}
// @__NO_SIDE_EFFECTS__
function Tt(t) {
  return Pi.call(t);
}
function Nt(t, e) {
  if (!ee)
    return /* @__PURE__ */ xt(t);
  var i = (
    /** @type {TemplateNode} */
    /* @__PURE__ */ xt(z)
  );
  return i === null && (i = z.appendChild(Fi())), _t(i), i;
}
function Ur(t) {
  t.textContent = "";
}
let ft = false, yt = false, Ct = null, ht = false, Qt = false;
function ui(t) {
  Qt = t;
}
let et = [];
let k = null, Q = false;
function ge(t) {
  k = t;
}
let T = null;
function _e(t) {
  T = t;
}
let se = null;
function Br(t) {
  se = t;
}
let N = null, q = 0, le = null;
function zr(t) {
  le = t;
}
let Ni = 1, Et = 0, me = false;
function Ui() {
  return ++Ni;
}
function Rt(t) {
  var _a2;
  var e = t.f;
  if ((e & Ce) !== 0)
    return true;
  if ((e & Be) !== 0) {
    var i = t.deps, r = (e & G) !== 0;
    if (i !== null) {
      var n, o, c = (e & vt) !== 0, f = r && T !== null && !me, h = i.length;
      if (c || f) {
        var d = (
          /** @type {Derived} */
          t
        ), p = d.parent;
        for (n = 0; n < h; n++)
          o = i[n], (c || !((_a2 = o == null ? void 0 : o.reactions) == null ? void 0 : _a2.includes(d))) && (o.reactions ?? (o.reactions = [])).push(d);
        c && (d.f ^= vt), f && p !== null && (p.f & G) === 0 && (d.f ^= G);
      }
      for (n = 0; n < h; n++)
        if (o = i[n], Rt(
          /** @type {Derived} */
          o
        ) && Ai(
          /** @type {Derived} */
          o
        ), o.wv > t.wv)
          return true;
    }
    (!r || T !== null && !me) && ce(t, j);
  }
  return false;
}
function Ir(t, e) {
  for (var i = e; i !== null; ) {
    if ((i.f & pt) !== 0)
      try {
        i.fn(t);
        return;
      } catch {
        i.f ^= pt;
      }
    i = i.parent;
  }
  throw ft = false, t;
}
function Wr(t) {
  return (t.f & Dt) === 0 && (t.parent === null || (t.parent.f & pt) === 0);
}
function $t(t, e, i, r) {
  if (ft) {
    if (i === null && (ft = false), Wr(e))
      throw t;
    return;
  }
  i !== null && (ft = true);
  {
    Ir(t, e);
    return;
  }
}
function Bi(t, e, i = true) {
  var r = t.reactions;
  if (r !== null)
    for (var n = 0; n < r.length; n++) {
      var o = r[n];
      (o.f & J) !== 0 ? Bi(
        /** @type {Derived} */
        o,
        e,
        false
      ) : e === o && (i ? ce(o, Ce) : (o.f & j) !== 0 && ce(o, Be), ei(
        /** @type {Effect} */
        o
      ));
    }
}
function zi(t) {
  var _a2;
  var e = N, i = q, r = le, n = k, o = me, c = se, f = B, h = Q, d = t.f;
  N = /** @type {null | Value[]} */
  null, q = 0, le = null, me = (d & G) !== 0 && (Q || !ht || k === null), k = (d & (ye | Ue)) === 0 ? t : null, se = null, ci(t.ctx), Q = false, Et++;
  try {
    var p = (
      /** @type {Function} */
      (0, t.fn)()
    ), w = t.deps;
    if (N !== null) {
      var s;
      if (kt(t, q), w !== null && q > 0)
        for (w.length = q + N.length, s = 0; s < N.length; s++)
          w[q + s] = N[s];
      else
        t.deps = w = N;
      if (!me)
        for (s = q; s < w.length; s++)
          ((_a2 = w[s]).reactions ?? (_a2.reactions = [])).push(t);
    } else w !== null && q < w.length && (kt(t, q), w.length = q);
    if (Xi() && le !== null && !Q && w !== null && (t.f & (J | Be | Ce)) === 0)
      for (s = 0; s < /** @type {Source[]} */
      le.length; s++)
        Bi(
          le[s],
          /** @type {Effect} */
          t
        );
    return n !== null && Et++, p;
  } finally {
    N = e, q = i, le = r, k = n, me = o, se = c, ci(f), Q = h;
  }
}
function Vr(t, e) {
  let i = e.reactions;
  if (i !== null) {
    var r = wr.call(i, t);
    if (r !== -1) {
      var n = i.length - 1;
      n === 0 ? i = e.reactions = null : (i[r] = i[n], i.pop());
    }
  }
  i === null && (e.f & J) !== 0 && // Destroying a child effect while updating a parent effect can cause a dependency to appear
  // to be unused, when in fact it is used by the currently-updating parent. Checking `new_deps`
  // allows us to skip the expensive work of disconnecting and immediately reconnecting it
  (N === null || !N.includes(e)) && (ce(e, Be), (e.f & (G | vt)) === 0 && (e.f ^= vt), $i(
    /** @type {Derived} **/
    e
  ), kt(
    /** @type {Derived} **/
    e,
    0
  ));
}
function kt(t, e) {
  var i = t.deps;
  if (i !== null)
    for (var r = e; r < i.length; r++)
      Vr(t, i[r]);
}
function Jt(t) {
  var e = t.f;
  if ((e & Dt) === 0) {
    ce(t, j);
    var i = T, r = B, n = ht;
    T = t, ht = true;
    try {
      (e & Yt) !== 0 ? nn(t) : Ki(t), Vi(t);
      var o = zi(t);
      t.teardown = typeof o == "function" ? o : null, t.wv = Ni;
      var c = t.deps, f;
      si && Lr && t.f & Ce;
    } catch (h) {
      $t(h, t, i, r || t.ctx);
    } finally {
      ht = n, T = i;
    }
  }
}
function Kr() {
  try {
    Dr();
  } catch (t) {
    if (Ct !== null)
      $t(t, Ct, null);
    else
      throw t;
  }
}
function Ii() {
  try {
    for (var t = 0; et.length > 0; ) {
      t++ > 1e3 && Kr();
      var e = et, i = e.length;
      et = [];
      for (var r = 0; r < i; r++) {
        var n = e[r];
        (n.f & j) === 0 && (n.f ^= j);
        var o = Hr(n);
        qr(o);
      }
    }
  } finally {
    yt = false, Ct = null;
  }
}
function qr(t) {
  var e = t.length;
  if (e !== 0)
    for (var i = 0; i < e; i++) {
      var r = t[i];
      if ((r.f & (Dt | wt)) === 0)
        try {
          Rt(r) && (Jt(r), r.deps === null && r.first === null && r.nodes_start === null && (r.teardown === null ? qi(r) : r.fn = null));
        } catch (n) {
          $t(n, r, null, r.ctx);
        }
    }
}
function ei(t) {
  yt || (yt = true, queueMicrotask(Ii));
  for (var e = Ct = t; e.parent !== null; ) {
    e = e.parent;
    var i = e.f;
    if ((i & (Ue | ye)) !== 0) {
      if ((i & j) === 0) return;
      e.f ^= j;
    }
  }
  et.push(e);
}
function Hr(t) {
  for (var e = [], i = t.first; i !== null; ) {
    var r = i.f, n = (r & ye) !== 0, o = n && (r & j) !== 0;
    if (!o && (r & wt) === 0) {
      if ((r & gi) !== 0)
        e.push(i);
      else if (n)
        i.f ^= j;
      else {
        var c = k;
        try {
          k = i, Rt(i) && Jt(i);
        } catch (d) {
          $t(d, i, null, i.ctx);
        } finally {
          k = c;
        }
      }
      var f = i.first;
      if (f !== null) {
        i = f;
        continue;
      }
    }
    var h = i.parent;
    for (i = i.next; i === null && h !== null; )
      i = h.next, h = h.parent;
  }
  return e;
}
function Ye(t) {
  var e;
  for (oi(); et.length > 0; )
    yt = true, Ii(), oi();
  return (
    /** @type {T} */
    e
  );
}
function U(t) {
  var e = t.f, i = (e & J) !== 0;
  if (k !== null && !Q) {
    se !== null && se.includes(t) && Ar();
    var r = k.deps;
    t.rv < Et && (t.rv = Et, N === null && r !== null && r[q] === t ? q++ : N === null ? N = [t] : (!me || !N.includes(t)) && N.push(t));
  } else if (i && /** @type {Derived} */
  t.deps === null && /** @type {Derived} */
  t.effects === null) {
    var n = (
      /** @type {Derived} */
      t
    ), o = n.parent;
    o !== null && (o.f & G) === 0 && (n.f ^= G);
  }
  return i && (n = /** @type {Derived} */
  t, Rt(n) && Ai(n)), t.v;
}
function it(t) {
  var e = Q;
  try {
    return Q = true, t();
  } finally {
    Q = e;
  }
}
const jr = -7169;
function ce(t, e) {
  t.f = t.f & jr | e;
}
function Gr(t) {
  T === null && k === null && Sr(), k !== null && (k.f & G) !== 0 && T === null && kr(), Qt && Er();
}
function Yr(t, e) {
  var i = e.last;
  i === null ? e.last = e.first = t : (i.next = t, t.prev = i, e.last = t);
}
function Se(t, e, i, r = true) {
  var n = (t & Ue) !== 0, o = T, c = {
    ctx: B,
    deps: null,
    nodes_start: null,
    nodes_end: null,
    f: t | Ce,
    first: null,
    fn: e,
    last: null,
    next: null,
    parent: n ? null : o,
    prev: null,
    teardown: null,
    transitions: null,
    wv: 0
  };
  if (i)
    try {
      Jt(c), c.f |= hr;
    } catch (d) {
      throw xe(c), d;
    }
  else e !== null && ei(c);
  var f = i && c.deps === null && c.first === null && c.nodes_start === null && c.teardown === null && (c.f & (_i | pt)) === 0;
  if (!f && !n && r && (o !== null && Yr(c, o), k !== null && (k.f & J) !== 0)) {
    var h = (
      /** @type {Derived} */
      k
    );
    (h.effects ?? (h.effects = [])).push(c);
  }
  return c;
}
function Xr(t) {
  const e = Se(St, null, false);
  return ce(e, j), e.teardown = t, e;
}
function Zr(t) {
  Gr();
  var e = T !== null && (T.f & ye) !== 0 && B !== null && !B.m;
  if (e) {
    var i = (
      /** @type {ComponentContext} */
      B
    );
    (i.e ?? (i.e = [])).push({
      fn: t,
      effect: T,
      reaction: k
    });
  } else {
    var r = ti(t);
    return r;
  }
}
function Qr(t) {
  const e = Se(Ue, t, true);
  return () => {
    xe(e);
  };
}
function Jr(t) {
  const e = Se(Ue, t, true);
  return (i = {}) => new Promise((r) => {
    i.outro ? sn(e, () => {
      xe(e), r(void 0);
    }) : (xe(e), r(void 0));
  });
}
function ti(t) {
  return Se(gi, t, false);
}
function Wi(t) {
  return Se(St, t, true);
}
function en(t, e = [], i = Ri) {
  const r = e.map(i);
  return tn(() => t(...r.map(U)));
}
function tn(t, e = 0) {
  return Se(St | Yt | e, t, true);
}
function rn(t, e = true) {
  return Se(St | ye, t, true, e);
}
function Vi(t) {
  var e = t.teardown;
  if (e !== null) {
    const i = Qt, r = k;
    ui(true), ge(null);
    try {
      e.call(null);
    } finally {
      ui(i), ge(r);
    }
  }
}
function Ki(t, e = false) {
  var i = t.first;
  for (t.first = t.last = null; i !== null; ) {
    var r = i.next;
    xe(i, e), i = r;
  }
}
function nn(t) {
  for (var e = t.first; e !== null; ) {
    var i = e.next;
    (e.f & ye) === 0 && xe(e), e = i;
  }
}
function xe(t, e = true) {
  var i = false;
  if ((e || (t.f & pr) !== 0) && t.nodes_start !== null) {
    for (var r = t.nodes_start, n = t.nodes_end; r !== null; ) {
      var o = r === n ? null : (
        /** @type {TemplateNode} */
        /* @__PURE__ */ Tt(r)
      );
      r.remove(), r = o;
    }
    i = true;
  }
  Ki(t, e && !i), kt(t, 0), ce(t, Dt);
  var c = t.transitions;
  if (c !== null)
    for (const h of c)
      h.stop();
  Vi(t);
  var f = t.parent;
  f !== null && f.first !== null && qi(t), t.next = t.prev = t.teardown = t.ctx = t.deps = t.fn = t.nodes_start = t.nodes_end = null;
}
function qi(t) {
  var e = t.parent, i = t.prev, r = t.next;
  i !== null && (i.next = r), r !== null && (r.prev = i), e !== null && (e.first === t && (e.first = r), e.last === t && (e.last = i));
}
function sn(t, e) {
  var i = [];
  Hi(t, i, true), on(i, () => {
    xe(t), e && e();
  });
}
function on(t, e) {
  var i = t.length;
  if (i > 0) {
    var r = () => --i || e();
    for (var n of t)
      n.out(r);
  } else
    e();
}
function Hi(t, e, i) {
  if ((t.f & wt) === 0) {
    if (t.f ^= wt, t.transitions !== null)
      for (const c of t.transitions)
        (c.is_global || i) && e.push(c);
    for (var r = t.first; r !== null; ) {
      var n = r.next, o = (r.f & br) !== 0 || (r.f & ye) !== 0;
      Hi(r, e, o ? i : false), r = n;
    }
  }
}
function ji(t) {
  throw new Error("https://svelte.dev/e/lifecycle_outside_component");
}
let B = null;
function ci(t) {
  B = t;
}
function Gi(t, e = false, i) {
  B = {
    p: B,
    c: null,
    e: null,
    m: false,
    s: t,
    x: null,
    l: null
  };
}
function Yi(t) {
  const e = B;
  if (e !== null) {
    t !== void 0 && (e.x = t);
    const c = e.e;
    if (c !== null) {
      var i = T, r = k;
      e.e = null;
      try {
        for (var n = 0; n < c.length; n++) {
          var o = c[n];
          _e(o.effect), ge(o.reaction), ti(o.fn);
        }
      } finally {
        _e(i), ge(r);
      }
    }
    B = e.p, e.m = true;
  }
  return t || /** @type {T} */
  {};
}
function Xi() {
  return true;
}
const an = ["touchstart", "touchmove"];
function ln(t) {
  return an.includes(t);
}
function un(t) {
  var e = k, i = T;
  ge(null), _e(null);
  try {
    return t();
  } finally {
    ge(e), _e(i);
  }
}
const Zi = /* @__PURE__ */ new Set(), Vt = /* @__PURE__ */ new Set();
function cn(t, e, i, r = {}) {
  function n(o) {
    if (r.capture || Xe.call(e, o), !o.cancelBubble)
      return un(() => i == null ? void 0 : i.call(this, o));
  }
  return t.startsWith("pointer") || t.startsWith("touch") || t === "wheel" ? Xt(() => {
    e.addEventListener(t, n, r);
  }) : e.addEventListener(t, n, r), n;
}
function lt(t, e, i, r, n) {
  var o = { capture: r, passive: n }, c = cn(t, e, i, o);
  (e === document.body || e === window || e === document) && Xr(() => {
    e.removeEventListener(t, c, o);
  });
}
function dn(t) {
  for (var e = 0; e < t.length; e++)
    Zi.add(t[e]);
  for (var i of Vt)
    i(t);
}
function Xe(t) {
  var _a2;
  var e = this, i = (
    /** @type {Node} */
    e.ownerDocument
  ), r = t.type, n = ((_a2 = t.composedPath) == null ? void 0 : _a2.call(t)) || [], o = (
    /** @type {null | Element} */
    n[0] || t.target
  ), c = 0, f = t.__root;
  if (f) {
    var h = n.indexOf(f);
    if (h !== -1 && (e === document || e === /** @type {any} */
    window)) {
      t.__root = e;
      return;
    }
    var d = n.indexOf(e);
    if (d === -1)
      return;
    h <= d && (c = h);
  }
  if (o = /** @type {Element} */
  n[c] || t.target, o !== e) {
    gt(t, "currentTarget", {
      configurable: true,
      get() {
        return o || i;
      }
    });
    var p = k, w = T;
    ge(null), _e(null);
    try {
      for (var s, a = []; o !== null; ) {
        var l = o.assignedSlot || o.parentNode || /** @type {any} */
        o.host || null;
        try {
          var u = o["__" + r];
          if (u !== void 0 && (!/** @type {any} */
          o.disabled || // DOM could've been updated already by the time this is reached, so we check this as well
          // -> the target could not have been disabled because it emits the event in the first place
          t.target === o))
            if (xi(u)) {
              var [b, ...$] = u;
              b.apply(o, [t, ...$]);
            } else
              u.call(o, t);
        } catch (P) {
          s ? a.push(P) : s = P;
        }
        if (t.cancelBubble || l === e || l === null)
          break;
        o = l;
      }
      if (s) {
        for (let P of a)
          queueMicrotask(() => {
            throw P;
          });
        throw s;
      }
    } finally {
      t.__root = e, delete t.currentTarget, ge(p), _e(w);
    }
  }
}
function fn(t) {
  var e = document.createElement("template");
  return e.innerHTML = t, e.content;
}
function Kt(t, e) {
  var i = (
    /** @type {Effect} */
    T
  );
  i.nodes_start === null && (i.nodes_start = t, i.nodes_end = e);
}
// @__NO_SIDE_EFFECTS__
function hn(t, e) {
  var i = (e & cr) !== 0, r, n = !t.startsWith("<!>");
  return () => {
    if (ee)
      return Kt(z, null), z;
    r === void 0 && (r = fn(n ? t : "<!>" + t), r = /** @type {Node} */
    /* @__PURE__ */ xt(r));
    var o = (
      /** @type {TemplateNode} */
      i || Li ? document.importNode(r, true) : r.cloneNode(true)
    );
    return Kt(o, o), o;
  };
}
function Qi(t, e) {
  if (ee) {
    T.nodes_end = z, Oi();
    return;
  }
  t !== null && t.before(
    /** @type {Node} */
    e
  );
}
function Ji(t, e) {
  return er(t, e);
}
function bn(t, e) {
  Wt(), e.intro = e.intro ?? false;
  const i = e.target, r = ee, n = z;
  try {
    for (var o = (
      /** @type {TemplateNode} */
      /* @__PURE__ */ xt(i)
    ); o && (o.nodeType !== 8 || /** @type {Comment} */
    o.data !== dr); )
      o = /** @type {TemplateNode} */
      /* @__PURE__ */ Tt(o);
    if (!o)
      throw Je;
    at(true), _t(
      /** @type {Comment} */
      o
    ), Oi();
    const c = er(t, { ...e, anchor: o });
    if (z === null || z.nodeType !== 8 || /** @type {Comment} */
    z.data !== fr)
      throw Zt(), Je;
    return at(false), /**  @type {Exports} */
    c;
  } catch (c) {
    if (c === Je)
      return e.recover === false && Tr(), Wt(), Ur(i), at(false), Ji(t, e);
    throw c;
  } finally {
    at(r), _t(n);
  }
}
const Le = /* @__PURE__ */ new Map();
function er(t, { target: e, anchor: i, props: r = {}, events: n, context: o, intro: c = true }) {
  Wt();
  var f = /* @__PURE__ */ new Set(), h = (w) => {
    for (var s = 0; s < w.length; s++) {
      var a = w[s];
      if (!f.has(a)) {
        f.add(a);
        var l = ln(a);
        e.addEventListener(a, Xe, { passive: l });
        var u = Le.get(a);
        u === void 0 ? (document.addEventListener(a, Xe, { passive: l }), Le.set(a, 1)) : Le.set(a, u + 1);
      }
    }
  };
  h(mr(Zi)), Vt.add(h);
  var d = void 0, p = Jr(() => {
    var w = i ?? e.appendChild(Fi());
    return rn(() => {
      if (o) {
        Gi({});
        var s = (
          /** @type {ComponentContext} */
          B
        );
        s.c = o;
      }
      n && (r.$$events = n), ee && Kt(
        /** @type {TemplateNode} */
        w,
        null
      ), d = t(w, r) || {}, ee && (T.nodes_end = z), o && Yi();
    }), () => {
      var _a2;
      for (var s of f) {
        e.removeEventListener(s, Xe);
        var a = (
          /** @type {number} */
          Le.get(s)
        );
        --a === 0 ? (document.removeEventListener(s, Xe), Le.delete(s)) : Le.set(s, a);
      }
      Vt.delete(h), w !== i && ((_a2 = w.parentNode) == null ? void 0 : _a2.removeChild(w));
    };
  });
  return qt.set(d, p), d;
}
let qt = /* @__PURE__ */ new WeakMap();
function pn(t, e) {
  const i = qt.get(t);
  return i ? (qt.delete(t), i(e)) : Promise.resolve();
}
function vn(t, e) {
  Xt(() => {
    var i = t.getRootNode(), r = (
      /** @type {ShadowRoot} */
      i.host ? (
        /** @type {ShadowRoot} */
        i
      ) : (
        /** @type {Document} */
        i.head ?? /** @type {Document} */
        i.ownerDocument.head
      )
    );
    if (!r.querySelector("#" + e.hash)) {
      const n = document.createElement("style");
      n.id = e.hash, n.textContent = e.code, r.appendChild(n);
    }
  });
}
const di = [...` 	
\r\f\xA0\v\uFEFF`];
function wn(t, e, i) {
  var r = t == null ? "" : "" + t;
  if (r = r ? r + " " + e : e, i) {
    for (var n in i)
      if (i[n])
        r = r ? r + " " + n : n;
      else if (r.length)
        for (var o = n.length, c = 0; (c = r.indexOf(n, c)) >= 0; ) {
          var f = c + o;
          (c === 0 || di.includes(r[c - 1])) && (f === r.length || di.includes(r[f])) ? r = (c === 0 ? "" : r.substring(0, c)) + r.substring(f + 1) : c = f;
        }
  }
  return r === "" ? null : r;
}
function mn(t, e, i, r, n, o) {
  var c = t.__className;
  if (ee || c !== i) {
    var f = wn(i, r, o);
    (!ee || f !== t.getAttribute("class")) && (f == null ? t.removeAttribute("class") : t.className = f), t.__className = i;
  } else if (o)
    for (var h in o) {
      var d = !!o[h];
      (n == null || d !== !!n[h]) && t.classList.toggle(h, d);
    }
  return o;
}
function fi(t, e, i, r) {
  var n = t.__attributes ?? (t.__attributes = {});
  ee && (n[e] = t.getAttribute(e)), n[e] !== (n[e] = i) && ("__styles" in t && (t.__styles = {}), i == null ? t.removeAttribute(e) : typeof i != "string" && gn(t).includes(e) ? t[e] = i : t.setAttribute(e, i));
}
var hi = /* @__PURE__ */ new Map();
function gn(t) {
  var e = hi.get(t.nodeName);
  if (e) return e;
  hi.set(t.nodeName, e = []);
  for (var i, r = t, n = Element.prototype; n !== r; ) {
    i = gr(r);
    for (var o in i)
      i[o].set && e.push(o);
    r = yi(r);
  }
  return e;
}
function bi(t, e) {
  return t === e || (t == null ? void 0 : t[ct]) === e;
}
function Ut(t = {}, e, i, r) {
  return ti(() => {
    var n, o;
    return Wi(() => {
      n = o, o = [], it(() => {
        t !== i(...o) && (e(t, ...o), n && bi(i(...n), t) && e(null, ...n));
      });
    }), () => {
      Xt(() => {
        o && bi(i(...o), t) && e(null, ...o);
      });
    };
  }), t;
}
function tr(t) {
  B === null && ji(), Zr(() => {
    const e = it(t);
    if (typeof e == "function") return (
      /** @type {() => void} */
      e
    );
  });
}
function _n(t) {
  B === null && ji(), tr(() => () => it(t));
}
function xn(t, e, i) {
  if (t == null)
    return e(void 0), dt;
  const r = it(
    () => t.subscribe(
      e,
      // @ts-expect-error
      i
    )
  );
  return r.unsubscribe ? () => r.unsubscribe() : r;
}
const Me = [];
function ir(t, e = dt) {
  let i = null;
  const r = /* @__PURE__ */ new Set();
  function n(f) {
    if (Si(t, f) && (t = f, i)) {
      const h = !Me.length;
      for (const d of r)
        d[1](), Me.push(d, t);
      if (h) {
        for (let d = 0; d < Me.length; d += 2)
          Me[d][0](Me[d + 1]);
        Me.length = 0;
      }
    }
  }
  function o(f) {
    n(f(
      /** @type {T} */
      t
    ));
  }
  function c(f, h = dt) {
    const d = [f, h];
    return r.add(d), r.size === 1 && (i = e(n, o) || dt), f(
      /** @type {T} */
      t
    ), () => {
      r.delete(d), r.size === 0 && i && (i(), i = null);
    };
  }
  return { set: n, update: o, subscribe: c };
}
function rr(t) {
  let e;
  return xn(t, (i) => e = i)(), e;
}
function ut(t, e, i, r) {
  var n;
  n = /** @type {V} */
  t[e];
  var o = (
    /** @type {V} */
    r
  ), c = true, f = false, h = () => (f = true, c && (c = false, o = /** @type {V} */
  r), o), d;
  d = () => {
    var a = (
      /** @type {V} */
      t[e]
    );
    return a === void 0 ? h() : (c = true, f = false, a);
  };
  var p = false, w = /* @__PURE__ */ Di(n), s = /* @__PURE__ */ Ri(() => {
    var a = d(), l = U(w);
    return p ? (p = false, l) : w.v = a;
  });
  return function(a, l) {
    if (arguments.length > 0) {
      const u = l ? U(s) : a;
      return s.equals(u) || (p = true, H(w, u), f && o !== void 0 && (o = u), it(() => U(s))), a;
    }
    return U(s);
  };
}
function yn(t) {
  return new Cn(t);
}
class Cn {
  /**
   * @param {ComponentConstructorOptions & {
   *  component: any;
   * }} options
   */
  constructor(e) {
    /** @type {any} */
    __privateAdd(this, _t2);
    /** @type {Record<string, any>} */
    __privateAdd(this, _e2);
    var _a2;
    var i = /* @__PURE__ */ new Map(), r = (o, c) => {
      var f = /* @__PURE__ */ Di(c);
      return i.set(o, f), f;
    };
    const n = new Proxy(
      { ...e.props || {}, $$events: {} },
      {
        get(o, c) {
          return U(i.get(c) ?? r(c, Reflect.get(o, c)));
        },
        has(o, c) {
          return c === vr ? true : (U(i.get(c) ?? r(c, Reflect.get(o, c))), Reflect.has(o, c));
        },
        set(o, c, f) {
          return H(i.get(c) ?? r(c, f), f), Reflect.set(o, c, f);
        }
      }
    );
    __privateSet(this, _e2, (e.hydrate ? bn : Ji)(e.component, {
      target: e.target,
      anchor: e.anchor,
      props: n,
      context: e.context,
      intro: e.intro ?? false,
      recover: e.recover
    })), (!((_a2 = e == null ? void 0 : e.props) == null ? void 0 : _a2.$$host) || e.sync === false) && Ye(), __privateSet(this, _t2, n.$$events);
    for (const o of Object.keys(__privateGet(this, _e2)))
      o === "$set" || o === "$destroy" || o === "$on" || gt(this, o, {
        get() {
          return __privateGet(this, _e2)[o];
        },
        /** @param {any} value */
        set(c) {
          __privateGet(this, _e2)[o] = c;
        },
        enumerable: true
      });
    __privateGet(this, _e2).$set = /** @param {Record<string, any>} next */
    (o) => {
      Object.assign(n, o);
    }, __privateGet(this, _e2).$destroy = () => {
      pn(__privateGet(this, _e2));
    };
  }
  /** @param {Record<string, any>} props */
  $set(e) {
    __privateGet(this, _e2).$set(e);
  }
  /**
   * @param {string} event
   * @param {(...args: any[]) => any} callback
   * @returns {any}
   */
  $on(e, i) {
    __privateGet(this, _t2)[e] = __privateGet(this, _t2)[e] || [];
    const r = (...n) => i.call(this, ...n);
    return __privateGet(this, _t2)[e].push(r), () => {
      __privateGet(this, _t2)[e] = __privateGet(this, _t2)[e].filter(
        /** @param {any} fn */
        (n) => n !== r
      );
    };
  }
  $destroy() {
    __privateGet(this, _e2).$destroy();
  }
}
_t2 = new WeakMap();
_e2 = new WeakMap();
let nr;
typeof HTMLElement == "function" && (nr = class extends HTMLElement {
  /**
   * @param {*} $$componentCtor
   * @param {*} $$slots
   * @param {*} use_shadow_dom
   */
  constructor(t, e, i) {
    super();
    /** The Svelte component constructor */
    __publicField(this, "$$ctor");
    /** Slots */
    __publicField(this, "$$s");
    /** @type {any} The Svelte component instance */
    __publicField(this, "$$c");
    /** Whether or not the custom element is connected */
    __publicField(this, "$$cn", false);
    /** @type {Record<string, any>} Component props data */
    __publicField(this, "$$d", {});
    /** `true` if currently in the process of reflecting component props back to attributes */
    __publicField(this, "$$r", false);
    /** @type {Record<string, CustomElementPropDefinition>} Props definition (name, reflected, type etc) */
    __publicField(this, "$$p_d", {});
    /** @type {Record<string, EventListenerOrEventListenerObject[]>} Event listeners */
    __publicField(this, "$$l", {});
    /** @type {Map<EventListenerOrEventListenerObject, Function>} Event listener unsubscribe functions */
    __publicField(this, "$$l_u", /* @__PURE__ */ new Map());
    /** @type {any} The managed render effect for reflecting attributes */
    __publicField(this, "$$me");
    this.$$ctor = t, this.$$s = e, i && this.attachShadow({ mode: "open" });
  }
  /**
   * @param {string} type
   * @param {EventListenerOrEventListenerObject} listener
   * @param {boolean | AddEventListenerOptions} [options]
   */
  addEventListener(t, e, i) {
    if (this.$$l[t] = this.$$l[t] || [], this.$$l[t].push(e), this.$$c) {
      const r = this.$$c.$on(t, e);
      this.$$l_u.set(e, r);
    }
    super.addEventListener(t, e, i);
  }
  /**
   * @param {string} type
   * @param {EventListenerOrEventListenerObject} listener
   * @param {boolean | AddEventListenerOptions} [options]
   */
  removeEventListener(t, e, i) {
    if (super.removeEventListener(t, e, i), this.$$c) {
      const r = this.$$l_u.get(e);
      r && (r(), this.$$l_u.delete(e));
    }
  }
  async connectedCallback() {
    if (this.$$cn = true, !this.$$c) {
      let t = function(r) {
        return (n) => {
          const o = document.createElement("slot");
          r !== "default" && (o.name = r), Qi(n, o);
        };
      };
      if (await Promise.resolve(), !this.$$cn || this.$$c)
        return;
      const e = {}, i = En(this);
      for (const r of this.$$s)
        r in i && (r === "default" && !this.$$d.children ? (this.$$d.children = t(r), e.default = true) : e[r] = t(r));
      for (const r of this.attributes) {
        const n = this.$$g_p(r.name);
        n in this.$$d || (this.$$d[n] = bt(n, r.value, this.$$p_d, "toProp"));
      }
      for (const r in this.$$p_d)
        !(r in this.$$d) && this[r] !== void 0 && (this.$$d[r] = this[r], delete this[r]);
      this.$$c = yn({
        component: this.$$ctor,
        target: this.shadowRoot || this,
        props: {
          ...this.$$d,
          $$slots: e,
          $$host: this
        }
      }), this.$$me = Qr(() => {
        Wi(() => {
          var _a2;
          this.$$r = true;
          for (const r of mt(this.$$c)) {
            if (!((_a2 = this.$$p_d[r]) == null ? void 0 : _a2.reflect)) continue;
            this.$$d[r] = this.$$c[r];
            const n = bt(
              r,
              this.$$d[r],
              this.$$p_d,
              "toAttribute"
            );
            n == null ? this.removeAttribute(this.$$p_d[r].attribute || r) : this.setAttribute(this.$$p_d[r].attribute || r, n);
          }
          this.$$r = false;
        });
      });
      for (const r in this.$$l)
        for (const n of this.$$l[r]) {
          const o = this.$$c.$on(r, n);
          this.$$l_u.set(n, o);
        }
      this.$$l = {};
    }
  }
  // We don't need this when working within Svelte code, but for compatibility of people using this outside of Svelte
  // and setting attributes through setAttribute etc, this is helpful
  /**
   * @param {string} attr
   * @param {string} _oldValue
   * @param {string} newValue
   */
  attributeChangedCallback(t, e, i) {
    var _a2;
    this.$$r || (t = this.$$g_p(t), this.$$d[t] = bt(t, i, this.$$p_d, "toProp"), (_a2 = this.$$c) == null ? void 0 : _a2.$set({ [t]: this.$$d[t] }));
  }
  disconnectedCallback() {
    this.$$cn = false, Promise.resolve().then(() => {
      !this.$$cn && this.$$c && (this.$$c.$destroy(), this.$$me(), this.$$c = void 0);
    });
  }
  /**
   * @param {string} attribute_name
   */
  $$g_p(t) {
    return mt(this.$$p_d).find(
      (e) => this.$$p_d[e].attribute === t || !this.$$p_d[e].attribute && e.toLowerCase() === t
    ) || t;
  }
});
function bt(t, e, i, r) {
  var _a2;
  const n = (_a2 = i[t]) == null ? void 0 : _a2.type;
  if (e = n === "Boolean" && typeof e != "boolean" ? e != null : e, !r || !i[t])
    return e;
  if (r === "toAttribute")
    switch (n) {
      case "Object":
      case "Array":
        return e == null ? null : JSON.stringify(e);
      case "Boolean":
        return e ? "" : null;
      case "Number":
        return e ?? null;
      default:
        return e;
    }
  else
    switch (n) {
      case "Object":
      case "Array":
        return e && JSON.parse(e);
      case "Boolean":
        return e;
      // conversion already handled above
      case "Number":
        return e != null ? +e : e;
      default:
        return e;
    }
}
function En(t) {
  const e = {};
  return t.childNodes.forEach((i) => {
    e[
      /** @type {Element} node */
      i.slot || "default"
    ] = true;
  }), e;
}
function kn(t, e, i, r, n, o) {
  let c = class extends nr {
    constructor() {
      super(t, i, n), this.$$p_d = e;
    }
    static get observedAttributes() {
      return mt(e).map(
        (f) => (e[f].attribute || f).toLowerCase()
      );
    }
  };
  return mt(e).forEach((f) => {
    gt(c.prototype, f, {
      get() {
        return this.$$c && f in this.$$c ? this.$$c[f] : this.$$d[f];
      },
      set(h) {
        var _a2;
        h = bt(f, h, e), this.$$d[f] = h;
        var d = this.$$c;
        if (d) {
          var p = (_a2 = Ne(d, f)) == null ? void 0 : _a2.get;
          p ? d[f] = h : d.$set({ [f]: h });
        }
      }
    });
  }), r.forEach((f) => {
    gt(c.prototype, f, {
      get() {
        var _a2;
        return (_a2 = this.$$c) == null ? void 0 : _a2[f];
      }
    });
  }), o && (c = o(c)), t.element = /** @type {any} */
  c, c;
}
class Sn {
  constructor() {
    __publicField(this, "verbose", false);
  }
  info(e) {
    this.verbose && console.log(e);
  }
  error(e, i) {
    this.verbose && console.error(e, i);
  }
}
const M = new Sn();
function Dn(t) {
  return t && t.__esModule && Object.prototype.hasOwnProperty.call(t, "default") ? t.default : t;
}
var Ze = { exports: {} }, Tn = Ze.exports, pi;
function Rn() {
  return pi || (pi = 1, (function(t, e) {
    (function(i, r) {
      var n = "1.0.41", o = "", c = "?", f = "function", h = "undefined", d = "object", p = "string", w = "major", s = "model", a = "name", l = "type", u = "vendor", b = "version", $ = "architecture", P = "console", _ = "mobile", m = "tablet", A = "smarttv", O = "wearable", de = "embedded", ze = 500, De = "Amazon", fe = "Apple", he = "ASUS", rt = "BlackBerry", Te = "Browser", Re = "Chrome", At = "Edge", Ee = "Firefox", $e = "Google", nt = "Honor", st = "Huawei", Ot = "Lenovo", be = "LG", Ie = "Microsoft", We = "Motorola", Ae = "Nvidia", Ve = "OnePlus", pe = "Opera", ve = "OPPO", Y = "Samsung", Ke = "Sharp", oe = "Sony", I = "Xiaomi", v = "Zebra", S = "Facebook", L = "Chromium OS", R = "Mac OS", F = " Browser", W = function(y, C) {
        var x = {};
        for (var D in y)
          C[D] && C[D].length % 2 === 0 ? x[D] = C[D].concat(y[D]) : x[D] = y[D];
        return x;
      }, X = function(y) {
        for (var C = {}, x = 0; x < y.length; x++)
          C[y[x].toUpperCase()] = y[x];
        return C;
      }, qe = function(y, C) {
        return typeof y === p ? He(C).indexOf(He(y)) !== -1 : false;
      }, He = function(y) {
        return y.toLowerCase();
      }, lr = function(y) {
        return typeof y === p ? y.replace(/[^\d\.]/g, o).split(".")[0] : r;
      }, Lt = function(y, C) {
        if (typeof y === p)
          return y = y.replace(/^\s\s*/, o), typeof C === h ? y : y.substring(0, ze);
      }, je = function(y, C) {
        for (var x = 0, D, ae, te, E, g, ie; x < C.length && !g; ) {
          var Mt = C[x], ni = C[x + 1];
          for (D = ae = 0; D < Mt.length && !g && Mt[D]; )
            if (g = Mt[D++].exec(y), g)
              for (te = 0; te < ni.length; te++)
                ie = g[++ae], E = ni[te], typeof E === d && E.length > 0 ? E.length === 2 ? typeof E[1] == f ? this[E[0]] = E[1].call(this, ie) : this[E[0]] = E[1] : E.length === 3 ? typeof E[1] === f && !(E[1].exec && E[1].test) ? this[E[0]] = ie ? E[1].call(this, ie, E[2]) : r : this[E[0]] = ie ? ie.replace(E[1], E[2]) : r : E.length === 4 && (this[E[0]] = ie ? E[3].call(this, ie.replace(E[1], E[2])) : r) : this[E] = ie || r;
          x += 2;
        }
      }, Ge = function(y, C) {
        for (var x in C)
          if (typeof C[x] === d && C[x].length > 0) {
            for (var D = 0; D < C[x].length; D++)
              if (qe(C[x][D], y))
                return x === c ? r : x;
          } else if (qe(C[x], y))
            return x === c ? r : x;
        return C.hasOwnProperty("*") ? C["*"] : y;
      }, ur = {
        "1.0": "/8",
        "1.2": "/1",
        "1.3": "/3",
        "2.0": "/412",
        "2.0.2": "/416",
        "2.0.3": "/417",
        "2.0.4": "/419",
        "?": "/"
      }, ii = {
        ME: "4.90",
        "NT 3.11": "NT3.51",
        "NT 4.0": "NT4.0",
        2e3: "NT 5.0",
        XP: ["NT 5.1", "NT 5.2"],
        Vista: "NT 6.0",
        7: "NT 6.1",
        8: "NT 6.2",
        "8.1": "NT 6.3",
        10: ["NT 6.4", "NT 10.0"],
        RT: "ARM"
      }, ri = {
        browser: [
          [
            /\b(?:crmo|crios)\/([\w\.]+)/i
            // Chrome for Android/iOS
          ],
          [b, [a, "Chrome"]],
          [
            /edg(?:e|ios|a)?\/([\w\.]+)/i
            // Microsoft Edge
          ],
          [b, [a, "Edge"]],
          [
            // Presto based
            /(opera mini)\/([-\w\.]+)/i,
            // Opera Mini
            /(opera [mobiletab]{3,6})\b.+version\/([-\w\.]+)/i,
            // Opera Mobi/Tablet
            /(opera)(?:.+version\/|[\/ ]+)([\w\.]+)/i
            // Opera
          ],
          [a, b],
          [
            /opios[\/ ]+([\w\.]+)/i
            // Opera mini on iphone >= 8.0
          ],
          [b, [a, pe + " Mini"]],
          [
            /\bop(?:rg)?x\/([\w\.]+)/i
            // Opera GX
          ],
          [b, [a, pe + " GX"]],
          [
            /\bopr\/([\w\.]+)/i
            // Opera Webkit
          ],
          [b, [a, pe]],
          [
            // Mixed
            /\bb[ai]*d(?:uhd|[ub]*[aekoprswx]{5,6})[\/ ]?([\w\.]+)/i
            // Baidu
          ],
          [b, [a, "Baidu"]],
          [
            /\b(?:mxbrowser|mxios|myie2)\/?([-\w\.]*)\b/i
            // Maxthon
          ],
          [b, [a, "Maxthon"]],
          [
            /(kindle)\/([\w\.]+)/i,
            // Kindle
            /(lunascape|maxthon|netfront|jasmine|blazer|sleipnir)[\/ ]?([\w\.]*)/i,
            // Lunascape/Maxthon/Netfront/Jasmine/Blazer/Sleipnir
            // Trident based
            /(avant|iemobile|slim(?:browser|boat|jet))[\/ ]?([\d\.]*)/i,
            // Avant/IEMobile/SlimBrowser/SlimBoat/Slimjet
            /(?:ms|\()(ie) ([\w\.]+)/i,
            // Internet Explorer
            // Blink/Webkit/KHTML based                                         // Flock/RockMelt/Midori/Epiphany/Silk/Skyfire/Bolt/Iron/Iridium/PhantomJS/Bowser/QupZilla/Falkon
            /(flock|rockmelt|midori|epiphany|silk|skyfire|ovibrowser|bolt|iron|vivaldi|iridium|phantomjs|bowser|qupzilla|falkon|rekonq|puffin|brave|whale(?!.+naver)|qqbrowserlite|duckduckgo|klar|helio|(?=comodo_)?dragon)\/([-\w\.]+)/i,
            // Rekonq/Puffin/Brave/Whale/QQBrowserLite/QQ//Vivaldi/DuckDuckGo/Klar/Helio/Dragon
            /(heytap|ovi|115)browser\/([\d\.]+)/i,
            // HeyTap/Ovi/115
            /(weibo)__([\d\.]+)/i
            // Weibo
          ],
          [a, b],
          [
            /quark(?:pc)?\/([-\w\.]+)/i
            // Quark
          ],
          [b, [a, "Quark"]],
          [
            /\bddg\/([\w\.]+)/i
            // DuckDuckGo
          ],
          [b, [a, "DuckDuckGo"]],
          [
            /(?:\buc? ?browser|(?:juc.+)ucweb)[\/ ]?([\w\.]+)/i
            // UCBrowser
          ],
          [b, [a, "UC" + Te]],
          [
            /microm.+\bqbcore\/([\w\.]+)/i,
            // WeChat Desktop for Windows Built-in Browser
            /\bqbcore\/([\w\.]+).+microm/i,
            /micromessenger\/([\w\.]+)/i
            // WeChat
          ],
          [b, [a, "WeChat"]],
          [
            /konqueror\/([\w\.]+)/i
            // Konqueror
          ],
          [b, [a, "Konqueror"]],
          [
            /trident.+rv[: ]([\w\.]{1,9})\b.+like gecko/i
            // IE11
          ],
          [b, [a, "IE"]],
          [
            /ya(?:search)?browser\/([\w\.]+)/i
            // Yandex
          ],
          [b, [a, "Yandex"]],
          [
            /slbrowser\/([\w\.]+)/i
            // Smart Lenovo Browser
          ],
          [b, [a, "Smart Lenovo " + Te]],
          [
            /(avast|avg)\/([\w\.]+)/i
            // Avast/AVG Secure Browser
          ],
          [[a, /(.+)/, "$1 Secure " + Te], b],
          [
            /\bfocus\/([\w\.]+)/i
            // Firefox Focus
          ],
          [b, [a, Ee + " Focus"]],
          [
            /\bopt\/([\w\.]+)/i
            // Opera Touch
          ],
          [b, [a, pe + " Touch"]],
          [
            /coc_coc\w+\/([\w\.]+)/i
            // Coc Coc Browser
          ],
          [b, [a, "Coc Coc"]],
          [
            /dolfin\/([\w\.]+)/i
            // Dolphin
          ],
          [b, [a, "Dolphin"]],
          [
            /coast\/([\w\.]+)/i
            // Opera Coast
          ],
          [b, [a, pe + " Coast"]],
          [
            /miuibrowser\/([\w\.]+)/i
            // MIUI Browser
          ],
          [b, [a, "MIUI" + F]],
          [
            /fxios\/([\w\.-]+)/i
            // Firefox for iOS
          ],
          [b, [a, Ee]],
          [
            /\bqihoobrowser\/?([\w\.]*)/i
            // 360
          ],
          [b, [a, "360"]],
          [
            /\b(qq)\/([\w\.]+)/i
            // QQ
          ],
          [[a, /(.+)/, "$1Browser"], b],
          [
            /(oculus|sailfish|huawei|vivo|pico)browser\/([\w\.]+)/i
          ],
          [[a, /(.+)/, "$1" + F], b],
          [
            // Oculus/Sailfish/HuaweiBrowser/VivoBrowser/PicoBrowser
            /samsungbrowser\/([\w\.]+)/i
            // Samsung Internet
          ],
          [b, [a, Y + " Internet"]],
          [
            /metasr[\/ ]?([\d\.]+)/i
            // Sogou Explorer
          ],
          [b, [a, "Sogou Explorer"]],
          [
            /(sogou)mo\w+\/([\d\.]+)/i
            // Sogou Mobile
          ],
          [[a, "Sogou Mobile"], b],
          [
            /(electron)\/([\w\.]+) safari/i,
            // Electron-based App
            /(tesla)(?: qtcarbrowser|\/(20\d\d\.[-\w\.]+))/i,
            // Tesla
            /m?(qqbrowser|2345(?=browser|chrome|explorer))\w*[\/ ]?v?([\w\.]+)/i
            // QQ/2345
          ],
          [a, b],
          [
            /(lbbrowser|rekonq)/i,
            // LieBao Browser/Rekonq
            /\[(linkedin)app\]/i
            // LinkedIn App for iOS & Android
          ],
          [a],
          [
            /ome\/([\w\.]+) \w* ?(iron) saf/i,
            // Iron
            /ome\/([\w\.]+).+qihu (360)[es]e/i
            // 360
          ],
          [b, a],
          [
            // WebView
            /((?:fban\/fbios|fb_iab\/fb4a)(?!.+fbav)|;fbav\/([\w\.]+);)/i
            // Facebook App for iOS & Android
          ],
          [[a, S], b],
          [
            /(Klarna)\/([\w\.]+)/i,
            // Klarna Shopping Browser for iOS & Android
            /(kakao(?:talk|story))[\/ ]([\w\.]+)/i,
            // Kakao App
            /(naver)\(.*?(\d+\.[\w\.]+).*\)/i,
            // Naver InApp
            /(daum)apps[\/ ]([\w\.]+)/i,
            // Daum App
            /safari (line)\/([\w\.]+)/i,
            // Line App for iOS
            /\b(line)\/([\w\.]+)\/iab/i,
            // Line App for Android
            /(alipay)client\/([\w\.]+)/i,
            // Alipay
            /(twitter)(?:and| f.+e\/([\w\.]+))/i,
            // Twitter
            /(chromium|instagram|snapchat)[\/ ]([-\w\.]+)/i
            // Chromium/Instagram/Snapchat
          ],
          [a, b],
          [
            /\bgsa\/([\w\.]+) .*safari\//i
            // Google Search Appliance on iOS
          ],
          [b, [a, "GSA"]],
          [
            /musical_ly(?:.+app_?version\/|_)([\w\.]+)/i
            // TikTok
          ],
          [b, [a, "TikTok"]],
          [
            /headlesschrome(?:\/([\w\.]+)| )/i
            // Chrome Headless
          ],
          [b, [a, Re + " Headless"]],
          [
            / wv\).+(chrome)\/([\w\.]+)/i
            // Chrome WebView
          ],
          [[a, Re + " WebView"], b],
          [
            /droid.+ version\/([\w\.]+)\b.+(?:mobile safari|safari)/i
            // Android Browser
          ],
          [b, [a, "Android " + Te]],
          [
            /(chrome|omniweb|arora|[tizenoka]{5} ?browser)\/v?([\w\.]+)/i
            // Chrome/OmniWeb/Arora/Tizen/Nokia
          ],
          [a, b],
          [
            /version\/([\w\.\,]+) .*mobile\/\w+ (safari)/i
            // Mobile Safari
          ],
          [b, [a, "Mobile Safari"]],
          [
            /version\/([\w(\.|\,)]+) .*(mobile ?safari|safari)/i
            // Safari & Safari Mobile
          ],
          [b, a],
          [
            /webkit.+?(mobile ?safari|safari)(\/[\w\.]+)/i
            // Safari < 3.0
          ],
          [a, [b, Ge, ur]],
          [
            /(webkit|khtml)\/([\w\.]+)/i
          ],
          [a, b],
          [
            // Gecko based
            /(navigator|netscape\d?)\/([-\w\.]+)/i
            // Netscape
          ],
          [[a, "Netscape"], b],
          [
            /(wolvic|librewolf)\/([\w\.]+)/i
            // Wolvic/LibreWolf
          ],
          [a, b],
          [
            /mobile vr; rv:([\w\.]+)\).+firefox/i
            // Firefox Reality
          ],
          [b, [a, Ee + " Reality"]],
          [
            /ekiohf.+(flow)\/([\w\.]+)/i,
            // Flow
            /(swiftfox)/i,
            // Swiftfox
            /(icedragon|iceweasel|camino|chimera|fennec|maemo browser|minimo|conkeror)[\/ ]?([\w\.\+]+)/i,
            // IceDragon/Iceweasel/Camino/Chimera/Fennec/Maemo/Minimo/Conkeror
            /(seamonkey|k-meleon|icecat|iceape|firebird|phoenix|palemoon|basilisk|waterfox)\/([-\w\.]+)$/i,
            // Firefox/SeaMonkey/K-Meleon/IceCat/IceApe/Firebird/Phoenix
            /(firefox)\/([\w\.]+)/i,
            // Other Firefox-based
            /(mozilla)\/([\w\.]+) .+rv\:.+gecko\/\d+/i,
            // Mozilla
            // Other
            /(amaya|dillo|doris|icab|ladybird|lynx|mosaic|netsurf|obigo|polaris|w3m|(?:go|ice|up)[\. ]?browser)[-\/ ]?v?([\w\.]+)/i,
            // Polaris/Lynx/Dillo/iCab/Doris/Amaya/w3m/NetSurf/Obigo/Mosaic/Go/ICE/UP.Browser/Ladybird
            /\b(links) \(([\w\.]+)/i
            // Links
          ],
          [a, [b, /_/g, "."]],
          [
            /(cobalt)\/([\w\.]+)/i
            // Cobalt
          ],
          [a, [b, /master.|lts./, ""]]
        ],
        cpu: [
          [
            /\b((amd|x|x86[-_]?|wow|win)64)\b/i
            // AMD64 (x64)
          ],
          [[$, "amd64"]],
          [
            /(ia32(?=;))/i,
            // IA32 (quicktime)
            /\b((i[346]|x)86)(pc)?\b/i
            // IA32 (x86)
          ],
          [[$, "ia32"]],
          [
            /\b(aarch64|arm(v?[89]e?l?|_?64))\b/i
            // ARM64
          ],
          [[$, "arm64"]],
          [
            /\b(arm(v[67])?ht?n?[fl]p?)\b/i
            // ARMHF
          ],
          [[$, "armhf"]],
          [
            // PocketPC mistakenly identified as PowerPC
            /( (ce|mobile); ppc;|\/[\w\.]+arm\b)/i
          ],
          [[$, "arm"]],
          [
            /((ppc|powerpc)(64)?)( mac|;|\))/i
            // PowerPC
          ],
          [[$, /ower/, o, He]],
          [
            / sun4\w[;\)]/i
            // SPARC
          ],
          [[$, "sparc"]],
          [
            /\b(avr32|ia64(?=;)|68k(?=\))|\barm(?=v([1-7]|[5-7]1)l?|;|eabi)|(irix|mips|sparc)(64)?\b|pa-risc)/i
            // IA64, 68K, ARM/64, AVR/32, IRIX/64, MIPS/64, SPARC/64, PA-RISC
          ],
          [[$, He]]
        ],
        device: [
          [
            //////////////////////////
            // MOBILES & TABLETS
            /////////////////////////
            // Samsung
            /\b(sch-i[89]0\d|shw-m380s|sm-[ptx]\w{2,4}|gt-[pn]\d{2,4}|sgh-t8[56]9|nexus 10)/i
          ],
          [s, [u, Y], [l, m]],
          [
            /\b((?:s[cgp]h|gt|sm)-(?![lr])\w+|sc[g-]?[\d]+a?|galaxy nexus)/i,
            /samsung[- ]((?!sm-[lr])[-\w]+)/i,
            /sec-(sgh\w+)/i
          ],
          [s, [u, Y], [l, _]],
          [
            // Apple
            /(?:\/|\()(ip(?:hone|od)[\w, ]*)(?:\/|;)/i
            // iPod/iPhone
          ],
          [s, [u, fe], [l, _]],
          [
            /\((ipad);[-\w\),; ]+apple/i,
            // iPad
            /applecoremedia\/[\w\.]+ \((ipad)/i,
            /\b(ipad)\d\d?,\d\d?[;\]].+ios/i
          ],
          [s, [u, fe], [l, m]],
          [
            /(macintosh);/i
          ],
          [s, [u, fe]],
          [
            // Sharp
            /\b(sh-?[altvz]?\d\d[a-ekm]?)/i
          ],
          [s, [u, Ke], [l, _]],
          [
            // Honor
            /\b((?:brt|eln|hey2?|gdi|jdn)-a?[lnw]09|(?:ag[rm]3?|jdn2|kob2)-a?[lw]0[09]hn)(?: bui|\)|;)/i
          ],
          [s, [u, nt], [l, m]],
          [
            /honor([-\w ]+)[;\)]/i
          ],
          [s, [u, nt], [l, _]],
          [
            // Huawei
            /\b((?:ag[rs][2356]?k?|bah[234]?|bg[2o]|bt[kv]|cmr|cpn|db[ry]2?|jdn2|got|kob2?k?|mon|pce|scm|sht?|[tw]gr|vrd)-[ad]?[lw][0125][09]b?|605hw|bg2-u03|(?:gem|fdr|m2|ple|t1)-[7a]0[1-4][lu]|t1-a2[13][lw]|mediapad[\w\. ]*(?= bui|\)))\b(?!.+d\/s)/i
          ],
          [s, [u, st], [l, m]],
          [
            /(?:huawei)([-\w ]+)[;\)]/i,
            /\b(nexus 6p|\w{2,4}e?-[atu]?[ln][\dx][012359c][adn]?)\b(?!.+d\/s)/i
          ],
          [s, [u, st], [l, _]],
          [
            // Xiaomi
            /oid[^\)]+; (2[\dbc]{4}(182|283|rp\w{2})[cgl]|m2105k81a?c)(?: bui|\))/i,
            /\b((?:red)?mi[-_ ]?pad[\w- ]*)(?: bui|\))/i
            // Mi Pad tablets
          ],
          [[s, /_/g, " "], [u, I], [l, m]],
          [
            /\b(poco[\w ]+|m2\d{3}j\d\d[a-z]{2})(?: bui|\))/i,
            // Xiaomi POCO
            /\b; (\w+) build\/hm\1/i,
            // Xiaomi Hongmi 'numeric' models
            /\b(hm[-_ ]?note?[_ ]?(?:\d\w)?) bui/i,
            // Xiaomi Hongmi
            /\b(redmi[\-_ ]?(?:note|k)?[\w_ ]+)(?: bui|\))/i,
            // Xiaomi Redmi
            /oid[^\)]+; (m?[12][0-389][01]\w{3,6}[c-y])( bui|; wv|\))/i,
            // Xiaomi Redmi 'numeric' models
            /\b(mi[-_ ]?(?:a\d|one|one[_ ]plus|note lte|max|cc)?[_ ]?(?:\d?\w?)[_ ]?(?:plus|se|lite|pro)?)(?: bui|\))/i,
            // Xiaomi Mi
            / ([\w ]+) miui\/v?\d/i
          ],
          [[s, /_/g, " "], [u, I], [l, _]],
          [
            // OPPO
            /; (\w+) bui.+ oppo/i,
            /\b(cph[12]\d{3}|p(?:af|c[al]|d\w|e[ar])[mt]\d0|x9007|a101op)\b/i
          ],
          [s, [u, ve], [l, _]],
          [
            /\b(opd2(\d{3}a?))(?: bui|\))/i
          ],
          [s, [u, Ge, { OnePlus: ["304", "403", "203"], "*": ve }], [l, m]],
          [
            // Vivo
            /vivo (\w+)(?: bui|\))/i,
            /\b(v[12]\d{3}\w?[at])(?: bui|;)/i
          ],
          [s, [u, "Vivo"], [l, _]],
          [
            // Realme
            /\b(rmx[1-3]\d{3})(?: bui|;|\))/i
          ],
          [s, [u, "Realme"], [l, _]],
          [
            // Motorola
            /\b(milestone|droid(?:[2-4x]| (?:bionic|x2|pro|razr))?:?( 4g)?)\b[\w ]+build\//i,
            /\bmot(?:orola)?[- ](\w*)/i,
            /((?:moto(?! 360)[\w\(\) ]+|xt\d{3,4}|nexus 6)(?= bui|\)))/i
          ],
          [s, [u, We], [l, _]],
          [
            /\b(mz60\d|xoom[2 ]{0,2}) build\//i
          ],
          [s, [u, We], [l, m]],
          [
            // LG
            /((?=lg)?[vl]k\-?\d{3}) bui| 3\.[-\w; ]{10}lg?-([06cv9]{3,4})/i
          ],
          [s, [u, be], [l, m]],
          [
            /(lm(?:-?f100[nv]?|-[\w\.]+)(?= bui|\))|nexus [45])/i,
            /\blg[-e;\/ ]+((?!browser|netcast|android tv|watch)\w+)/i,
            /\blg-?([\d\w]+) bui/i
          ],
          [s, [u, be], [l, _]],
          [
            // Lenovo
            /(ideatab[-\w ]+|602lv|d-42a|a101lv|a2109a|a3500-hv|s[56]000|pb-6505[my]|tb-?x?\d{3,4}(?:f[cu]|xu|[av])|yt\d?-[jx]?\d+[lfmx])( bui|;|\)|\/)/i,
            /lenovo ?(b[68]0[08]0-?[hf]?|tab(?:[\w- ]+?)|tb[\w-]{6,7})( bui|;|\)|\/)/i
          ],
          [s, [u, Ot], [l, m]],
          [
            // Nokia
            /(nokia) (t[12][01])/i
          ],
          [u, s, [l, m]],
          [
            /(?:maemo|nokia).*(n900|lumia \d+|rm-\d+)/i,
            /nokia[-_ ]?(([-\w\. ]*))/i
          ],
          [[s, /_/g, " "], [l, _], [u, "Nokia"]],
          [
            // Google
            /(pixel (c|tablet))\b/i
            // Google Pixel C/Tablet
          ],
          [s, [u, $e], [l, m]],
          [
            /droid.+; (pixel[\daxl ]{0,6})(?: bui|\))/i
            // Google Pixel
          ],
          [s, [u, $e], [l, _]],
          [
            // Sony
            /droid.+; (a?\d[0-2]{2}so|[c-g]\d{4}|so[-gl]\w+|xq-a\w[4-7][12])(?= bui|\).+chrome\/(?![1-6]{0,1}\d\.))/i
          ],
          [s, [u, oe], [l, _]],
          [
            /sony tablet [ps]/i,
            /\b(?:sony)?sgp\w+(?: bui|\))/i
          ],
          [[s, "Xperia Tablet"], [u, oe], [l, m]],
          [
            // OnePlus
            / (kb2005|in20[12]5|be20[12][59])\b/i,
            /(?:one)?(?:plus)? (a\d0\d\d)(?: b|\))/i
          ],
          [s, [u, Ve], [l, _]],
          [
            // Amazon
            /(alexa)webm/i,
            /(kf[a-z]{2}wi|aeo(?!bc)\w\w)( bui|\))/i,
            // Kindle Fire without Silk / Echo Show
            /(kf[a-z]+)( bui|\)).+silk\//i
            // Kindle Fire HD
          ],
          [s, [u, De], [l, m]],
          [
            /((?:sd|kf)[0349hijorstuw]+)( bui|\)).+silk\//i
            // Fire Phone
          ],
          [[s, /(.+)/g, "Fire Phone $1"], [u, De], [l, _]],
          [
            // BlackBerry
            /(playbook);[-\w\),; ]+(rim)/i
            // BlackBerry PlayBook
          ],
          [s, u, [l, m]],
          [
            /\b((?:bb[a-f]|st[hv])100-\d)/i,
            /\(bb10; (\w+)/i
            // BlackBerry 10
          ],
          [s, [u, rt], [l, _]],
          [
            // Asus
            /(?:\b|asus_)(transfo[prime ]{4,10} \w+|eeepc|slider \w+|nexus 7|padfone|p00[cj])/i
          ],
          [s, [u, he], [l, m]],
          [
            / (z[bes]6[027][012][km][ls]|zenfone \d\w?)\b/i
          ],
          [s, [u, he], [l, _]],
          [
            // HTC
            /(nexus 9)/i
            // HTC Nexus 9
          ],
          [s, [u, "HTC"], [l, m]],
          [
            /(htc)[-;_ ]{1,2}([\w ]+(?=\)| bui)|\w+)/i,
            // HTC
            // ZTE
            /(zte)[- ]([\w ]+?)(?: bui|\/|\))/i,
            /(alcatel|geeksphone|nexian|panasonic(?!(?:;|\.))|sony(?!-bra))[-_ ]?([-\w]*)/i
            // Alcatel/GeeksPhone/Nexian/Panasonic/Sony
          ],
          [u, [s, /_/g, " "], [l, _]],
          [
            // TCL
            /droid [\w\.]+; ((?:8[14]9[16]|9(?:0(?:48|60|8[01])|1(?:3[27]|66)|2(?:6[69]|9[56])|466))[gqswx])\w*(\)| bui)/i
          ],
          [s, [u, "TCL"], [l, m]],
          [
            // itel
            /(itel) ((\w+))/i
          ],
          [[u, He], s, [l, Ge, { tablet: ["p10001l", "w7001"], "*": "mobile" }]],
          [
            // Acer
            /droid.+; ([ab][1-7]-?[0178a]\d\d?)/i
          ],
          [s, [u, "Acer"], [l, m]],
          [
            // Meizu
            /droid.+; (m[1-5] note) bui/i,
            /\bmz-([-\w]{2,})/i
          ],
          [s, [u, "Meizu"], [l, _]],
          [
            // Ulefone
            /; ((?:power )?armor(?:[\w ]{0,8}))(?: bui|\))/i
          ],
          [s, [u, "Ulefone"], [l, _]],
          [
            // Energizer
            /; (energy ?\w+)(?: bui|\))/i,
            /; energizer ([\w ]+)(?: bui|\))/i
          ],
          [s, [u, "Energizer"], [l, _]],
          [
            // Cat
            /; cat (b35);/i,
            /; (b15q?|s22 flip|s48c|s62 pro)(?: bui|\))/i
          ],
          [s, [u, "Cat"], [l, _]],
          [
            // Smartfren
            /((?:new )?andromax[\w- ]+)(?: bui|\))/i
          ],
          [s, [u, "Smartfren"], [l, _]],
          [
            // Nothing
            /droid.+; (a(?:015|06[35]|142p?))/i
          ],
          [s, [u, "Nothing"], [l, _]],
          [
            // Archos
            /; (x67 5g|tikeasy \w+|ac[1789]\d\w+)( b|\))/i,
            /archos ?(5|gamepad2?|([\w ]*[t1789]|hello) ?\d+[\w ]*)( b|\))/i
          ],
          [s, [u, "Archos"], [l, m]],
          [
            /archos ([\w ]+)( b|\))/i,
            /; (ac[3-6]\d\w{2,8})( b|\))/i
          ],
          [s, [u, "Archos"], [l, _]],
          [
            // MIXED
            /(imo) (tab \w+)/i,
            // IMO
            /(infinix) (x1101b?)/i
            // Infinix XPad
          ],
          [u, s, [l, m]],
          [
            /(blackberry|benq|palm(?=\-)|sonyericsson|acer|asus(?! zenw)|dell|jolla|meizu|motorola|polytron|infinix|tecno|micromax|advan)[-_ ]?([-\w]*)/i,
            // BlackBerry/BenQ/Palm/Sony-Ericsson/Acer/Asus/Dell/Meizu/Motorola/Polytron/Infinix/Tecno/Micromax/Advan
            /; (hmd|imo) ([\w ]+?)(?: bui|\))/i,
            // HMD/IMO
            /(hp) ([\w ]+\w)/i,
            // HP iPAQ
            /(microsoft); (lumia[\w ]+)/i,
            // Microsoft Lumia
            /(lenovo)[-_ ]?([-\w ]+?)(?: bui|\)|\/)/i,
            // Lenovo
            /(oppo) ?([\w ]+) bui/i
            // OPPO
          ],
          [u, s, [l, _]],
          [
            /(kobo)\s(ereader|touch)/i,
            // Kobo
            /(hp).+(touchpad(?!.+tablet)|tablet)/i,
            // HP TouchPad
            /(kindle)\/([\w\.]+)/i,
            // Kindle
            /(nook)[\w ]+build\/(\w+)/i,
            // Nook
            /(dell) (strea[kpr\d ]*[\dko])/i,
            // Dell Streak
            /(le[- ]+pan)[- ]+(\w{1,9}) bui/i,
            // Le Pan Tablets
            /(trinity)[- ]*(t\d{3}) bui/i,
            // Trinity Tablets
            /(gigaset)[- ]+(q\w{1,9}) bui/i,
            // Gigaset Tablets
            /(vodafone) ([\w ]+)(?:\)| bui)/i
            // Vodafone
          ],
          [u, s, [l, m]],
          [
            /(surface duo)/i
            // Surface Duo
          ],
          [s, [u, Ie], [l, m]],
          [
            /droid [\d\.]+; (fp\du?)(?: b|\))/i
            // Fairphone
          ],
          [s, [u, "Fairphone"], [l, _]],
          [
            /(u304aa)/i
            // AT&T
          ],
          [s, [u, "AT&T"], [l, _]],
          [
            /\bsie-(\w*)/i
            // Siemens
          ],
          [s, [u, "Siemens"], [l, _]],
          [
            /\b(rct\w+) b/i
            // RCA Tablets
          ],
          [s, [u, "RCA"], [l, m]],
          [
            /\b(venue[\d ]{2,7}) b/i
            // Dell Venue Tablets
          ],
          [s, [u, "Dell"], [l, m]],
          [
            /\b(q(?:mv|ta)\w+) b/i
            // Verizon Tablet
          ],
          [s, [u, "Verizon"], [l, m]],
          [
            /\b(?:barnes[& ]+noble |bn[rt])([\w\+ ]*) b/i
            // Barnes & Noble Tablet
          ],
          [s, [u, "Barnes & Noble"], [l, m]],
          [
            /\b(tm\d{3}\w+) b/i
          ],
          [s, [u, "NuVision"], [l, m]],
          [
            /\b(k88) b/i
            // ZTE K Series Tablet
          ],
          [s, [u, "ZTE"], [l, m]],
          [
            /\b(nx\d{3}j) b/i
            // ZTE Nubia
          ],
          [s, [u, "ZTE"], [l, _]],
          [
            /\b(gen\d{3}) b.+49h/i
            // Swiss GEN Mobile
          ],
          [s, [u, "Swiss"], [l, _]],
          [
            /\b(zur\d{3}) b/i
            // Swiss ZUR Tablet
          ],
          [s, [u, "Swiss"], [l, m]],
          [
            /\b((zeki)?tb.*\b) b/i
            // Zeki Tablets
          ],
          [s, [u, "Zeki"], [l, m]],
          [
            /\b([yr]\d{2}) b/i,
            /\b(dragon[- ]+touch |dt)(\w{5}) b/i
            // Dragon Touch Tablet
          ],
          [[u, "Dragon Touch"], s, [l, m]],
          [
            /\b(ns-?\w{0,9}) b/i
            // Insignia Tablets
          ],
          [s, [u, "Insignia"], [l, m]],
          [
            /\b((nxa|next)-?\w{0,9}) b/i
            // NextBook Tablets
          ],
          [s, [u, "NextBook"], [l, m]],
          [
            /\b(xtreme\_)?(v(1[045]|2[015]|[3469]0|7[05])) b/i
            // Voice Xtreme Phones
          ],
          [[u, "Voice"], s, [l, _]],
          [
            /\b(lvtel\-)?(v1[12]) b/i
            // LvTel Phones
          ],
          [[u, "LvTel"], s, [l, _]],
          [
            /\b(ph-1) /i
            // Essential PH-1
          ],
          [s, [u, "Essential"], [l, _]],
          [
            /\b(v(100md|700na|7011|917g).*\b) b/i
            // Envizen Tablets
          ],
          [s, [u, "Envizen"], [l, m]],
          [
            /\b(trio[-\w\. ]+) b/i
            // MachSpeed Tablets
          ],
          [s, [u, "MachSpeed"], [l, m]],
          [
            /\btu_(1491) b/i
            // Rotor Tablets
          ],
          [s, [u, "Rotor"], [l, m]],
          [
            /((?:tegranote|shield t(?!.+d tv))[\w- ]*?)(?: b|\))/i
            // Nvidia Tablets
          ],
          [s, [u, Ae], [l, m]],
          [
            /(sprint) (\w+)/i
            // Sprint Phones
          ],
          [u, s, [l, _]],
          [
            /(kin\.[onetw]{3})/i
            // Microsoft Kin
          ],
          [[s, /\./g, " "], [u, Ie], [l, _]],
          [
            /droid.+; (cc6666?|et5[16]|mc[239][23]x?|vc8[03]x?)\)/i
            // Zebra
          ],
          [s, [u, v], [l, m]],
          [
            /droid.+; (ec30|ps20|tc[2-8]\d[kx])\)/i
          ],
          [s, [u, v], [l, _]],
          [
            ///////////////////
            // SMARTTVS
            ///////////////////
            /smart-tv.+(samsung)/i
            // Samsung
          ],
          [u, [l, A]],
          [
            /hbbtv.+maple;(\d+)/i
          ],
          [[s, /^/, "SmartTV"], [u, Y], [l, A]],
          [
            /(nux; netcast.+smarttv|lg (netcast\.tv-201\d|android tv))/i
            // LG SmartTV
          ],
          [[u, be], [l, A]],
          [
            /(apple) ?tv/i
            // Apple TV
          ],
          [u, [s, fe + " TV"], [l, A]],
          [
            /crkey/i
            // Google Chromecast
          ],
          [[s, Re + "cast"], [u, $e], [l, A]],
          [
            /droid.+aft(\w+)( bui|\))/i
            // Fire TV
          ],
          [s, [u, De], [l, A]],
          [
            /(shield \w+ tv)/i
            // Nvidia Shield TV
          ],
          [s, [u, Ae], [l, A]],
          [
            /\(dtv[\);].+(aquos)/i,
            /(aquos-tv[\w ]+)\)/i
            // Sharp
          ],
          [s, [u, Ke], [l, A]],
          [
            /(bravia[\w ]+)( bui|\))/i
            // Sony
          ],
          [s, [u, oe], [l, A]],
          [
            /(mi(tv|box)-?\w+) bui/i
            // Xiaomi
          ],
          [s, [u, I], [l, A]],
          [
            /Hbbtv.*(technisat) (.*);/i
            // TechniSAT
          ],
          [u, s, [l, A]],
          [
            /\b(roku)[\dx]*[\)\/]((?:dvp-)?[\d\.]*)/i,
            // Roku
            /hbbtv\/\d+\.\d+\.\d+ +\([\w\+ ]*; *([\w\d][^;]*);([^;]*)/i
            // HbbTV devices
          ],
          [[u, Lt], [s, Lt], [l, A]],
          [
            // SmartTV from Unidentified Vendors
            /droid.+; ([\w- ]+) (?:android tv|smart[- ]?tv)/i
          ],
          [s, [l, A]],
          [
            /\b(android tv|smart[- ]?tv|opera tv|tv; rv:)\b/i
          ],
          [[l, A]],
          [
            ///////////////////
            // CONSOLES
            ///////////////////
            /(ouya)/i,
            // Ouya
            /(nintendo) ([wids3utch]+)/i
            // Nintendo
          ],
          [u, s, [l, P]],
          [
            /droid.+; (shield)( bui|\))/i
            // Nvidia Portable
          ],
          [s, [u, Ae], [l, P]],
          [
            /(playstation \w+)/i
            // Playstation
          ],
          [s, [u, oe], [l, P]],
          [
            /\b(xbox(?: one)?(?!; xbox))[\); ]/i
            // Microsoft Xbox
          ],
          [s, [u, Ie], [l, P]],
          [
            ///////////////////
            // WEARABLES
            ///////////////////
            /\b(sm-[lr]\d\d[0156][fnuw]?s?|gear live)\b/i
            // Samsung Galaxy Watch
          ],
          [s, [u, Y], [l, O]],
          [
            /((pebble))app/i,
            // Pebble
            /(asus|google|lg|oppo) ((pixel |zen)?watch[\w ]*)( bui|\))/i
            // Asus ZenWatch / LG Watch / Pixel Watch
          ],
          [u, s, [l, O]],
          [
            /(ow(?:19|20)?we?[1-3]{1,3})/i
            // Oppo Watch
          ],
          [s, [u, ve], [l, O]],
          [
            /(watch)(?: ?os[,\/]|\d,\d\/)[\d\.]+/i
            // Apple Watch
          ],
          [s, [u, fe], [l, O]],
          [
            /(opwwe\d{3})/i
            // OnePlus Watch
          ],
          [s, [u, Ve], [l, O]],
          [
            /(moto 360)/i
            // Motorola 360
          ],
          [s, [u, We], [l, O]],
          [
            /(smartwatch 3)/i
            // Sony SmartWatch
          ],
          [s, [u, oe], [l, O]],
          [
            /(g watch r)/i
            // LG G Watch R
          ],
          [s, [u, be], [l, O]],
          [
            /droid.+; (wt63?0{2,3})\)/i
          ],
          [s, [u, v], [l, O]],
          [
            ///////////////////
            // XR
            ///////////////////
            /droid.+; (glass) \d/i
            // Google Glass
          ],
          [s, [u, $e], [l, O]],
          [
            /(pico) (4|neo3(?: link|pro)?)/i
            // Pico
          ],
          [u, s, [l, O]],
          [
            /; (quest( \d| pro)?)/i
            // Oculus Quest
          ],
          [s, [u, S], [l, O]],
          [
            ///////////////////
            // EMBEDDED
            ///////////////////
            /(tesla)(?: qtcarbrowser|\/[-\w\.]+)/i
            // Tesla
          ],
          [u, [l, de]],
          [
            /(aeobc)\b/i
            // Echo Dot
          ],
          [s, [u, De], [l, de]],
          [
            /(homepod).+mac os/i
            // Apple HomePod
          ],
          [s, [u, fe], [l, de]],
          [
            /windows iot/i
          ],
          [[l, de]],
          [
            ////////////////////
            // MIXED (GENERIC)
            ///////////////////
            /droid .+?; ([^;]+?)(?: bui|; wv\)|\) applew).+? mobile safari/i
            // Android Phones from Unidentified Vendors
          ],
          [s, [l, _]],
          [
            /droid .+?; ([^;]+?)(?: bui|\) applew).+?(?! mobile) safari/i
            // Android Tablets from Unidentified Vendors
          ],
          [s, [l, m]],
          [
            /\b((tablet|tab)[;\/]|focus\/\d(?!.+mobile))/i
            // Unidentifiable Tablet
          ],
          [[l, m]],
          [
            /(phone|mobile(?:[;\/]| [ \w\/\.]*safari)|pda(?=.+windows ce))/i
            // Unidentifiable Mobile
          ],
          [[l, _]],
          [
            /droid .+?; ([\w\. -]+)( bui|\))/i
            // Generic Android Device
          ],
          [s, [u, "Generic"]]
        ],
        engine: [
          [
            /windows.+ edge\/([\w\.]+)/i
            // EdgeHTML
          ],
          [b, [a, At + "HTML"]],
          [
            /(arkweb)\/([\w\.]+)/i
            // ArkWeb
          ],
          [a, b],
          [
            /webkit\/537\.36.+chrome\/(?!27)([\w\.]+)/i
            // Blink
          ],
          [b, [a, "Blink"]],
          [
            /(presto)\/([\w\.]+)/i,
            // Presto
            /(webkit|trident|netfront|netsurf|amaya|lynx|w3m|goanna|servo)\/([\w\.]+)/i,
            // WebKit/Trident/NetFront/NetSurf/Amaya/Lynx/w3m/Goanna/Servo
            /ekioh(flow)\/([\w\.]+)/i,
            // Flow
            /(khtml|tasman|links)[\/ ]\(?([\w\.]+)/i,
            // KHTML/Tasman/Links
            /(icab)[\/ ]([23]\.[\d\.]+)/i,
            // iCab
            /\b(libweb)/i
            // LibWeb
          ],
          [a, b],
          [
            /ladybird\//i
          ],
          [[a, "LibWeb"]],
          [
            /rv\:([\w\.]{1,9})\b.+(gecko)/i
            // Gecko
          ],
          [b, a]
        ],
        os: [
          [
            // Windows
            /microsoft (windows) (vista|xp)/i
            // Windows (iTunes)
          ],
          [a, b],
          [
            /(windows (?:phone(?: os)?|mobile|iot))[\/ ]?([\d\.\w ]*)/i
            // Windows Phone
          ],
          [a, [b, Ge, ii]],
          [
            /windows nt 6\.2; (arm)/i,
            // Windows RT
            /windows[\/ ]([ntce\d\. ]+\w)(?!.+xbox)/i,
            /(?:win(?=3|9|n)|win 9x )([nt\d\.]+)/i
          ],
          [[b, Ge, ii], [a, "Windows"]],
          [
            // iOS/macOS
            /[adehimnop]{4,7}\b(?:.*os ([\w]+) like mac|; opera)/i,
            // iOS
            /(?:ios;fbsv\/|iphone.+ios[\/ ])([\d\.]+)/i,
            /cfnetwork\/.+darwin/i
          ],
          [[b, /_/g, "."], [a, "iOS"]],
          [
            /(mac os x) ?([\w\. ]*)/i,
            /(macintosh|mac_powerpc\b)(?!.+haiku)/i
            // Mac OS
          ],
          [[a, R], [b, /_/g, "."]],
          [
            // Mobile OSes
            /droid ([\w\.]+)\b.+(android[- ]x86|harmonyos)/i
            // Android-x86/HarmonyOS
          ],
          [b, a],
          [
            /(ubuntu) ([\w\.]+) like android/i
            // Ubuntu Touch
          ],
          [[a, /(.+)/, "$1 Touch"], b],
          [
            // Android/Blackberry/WebOS/QNX/Bada/RIM/KaiOS/Maemo/MeeGo/S40/Sailfish OS/OpenHarmony/Tizen
            /(android|bada|blackberry|kaios|maemo|meego|openharmony|qnx|rim tablet os|sailfish|series40|symbian|tizen|webos)\w*[-\/; ]?([\d\.]*)/i
          ],
          [a, b],
          [
            /\(bb(10);/i
            // BlackBerry 10
          ],
          [b, [a, rt]],
          [
            /(?:symbian ?os|symbos|s60(?=;)|series ?60)[-\/ ]?([\w\.]*)/i
            // Symbian
          ],
          [b, [a, "Symbian"]],
          [
            /mozilla\/[\d\.]+ \((?:mobile|tablet|tv|mobile; [\w ]+); rv:.+ gecko\/([\w\.]+)/i
            // Firefox OS
          ],
          [b, [a, Ee + " OS"]],
          [
            /web0s;.+rt(tv)/i,
            /\b(?:hp)?wos(?:browser)?\/([\w\.]+)/i
            // WebOS
          ],
          [b, [a, "webOS"]],
          [
            /watch(?: ?os[,\/]|\d,\d\/)([\d\.]+)/i
            // watchOS
          ],
          [b, [a, "watchOS"]],
          [
            // Google Chromecast
            /crkey\/([\d\.]+)/i
            // Google Chromecast
          ],
          [b, [a, Re + "cast"]],
          [
            /(cros) [\w]+(?:\)| ([\w\.]+)\b)/i
            // Chromium OS
          ],
          [[a, L], b],
          [
            // Smart TVs
            /panasonic;(viera)/i,
            // Panasonic Viera
            /(netrange)mmh/i,
            // Netrange
            /(nettv)\/(\d+\.[\w\.]+)/i,
            // NetTV
            // Console
            /(nintendo|playstation) ([wids345portablevuch]+)/i,
            // Nintendo/Playstation
            /(xbox); +xbox ([^\);]+)/i,
            // Microsoft Xbox (360, One, X, S, Series X, Series S)
            // Other
            /\b(joli|palm)\b ?(?:os)?\/?([\w\.]*)/i,
            // Joli/Palm
            /(mint)[\/\(\) ]?(\w*)/i,
            // Mint
            /(mageia|vectorlinux)[; ]/i,
            // Mageia/VectorLinux
            /([kxln]?ubuntu|debian|suse|opensuse|gentoo|arch(?= linux)|slackware|fedora|mandriva|centos|pclinuxos|red ?hat|zenwalk|linpus|raspbian|plan 9|minix|risc os|contiki|deepin|manjaro|elementary os|sabayon|linspire)(?: gnu\/linux)?(?: enterprise)?(?:[- ]linux)?(?:-gnu)?[-\/ ]?(?!chrom|package)([-\w\.]*)/i,
            // Ubuntu/Debian/SUSE/Gentoo/Arch/Slackware/Fedora/Mandriva/CentOS/PCLinuxOS/RedHat/Zenwalk/Linpus/Raspbian/Plan9/Minix/RISCOS/Contiki/Deepin/Manjaro/elementary/Sabayon/Linspire
            /(hurd|linux)(?: arm\w*| x86\w*| ?)([\w\.]*)/i,
            // Hurd/Linux
            /(gnu) ?([\w\.]*)/i,
            // GNU
            /\b([-frentopcghs]{0,5}bsd|dragonfly)[\/ ]?(?!amd|[ix346]{1,2}86)([\w\.]*)/i,
            // FreeBSD/NetBSD/OpenBSD/PC-BSD/GhostBSD/DragonFly
            /(haiku) (\w+)/i
            // Haiku
          ],
          [a, b],
          [
            /(sunos) ?([\w\.\d]*)/i
            // Solaris
          ],
          [[a, "Solaris"], b],
          [
            /((?:open)?solaris)[-\/ ]?([\w\.]*)/i,
            // Solaris
            /(aix) ((\d)(?=\.|\)| )[\w\.])*/i,
            // AIX
            /\b(beos|os\/2|amigaos|morphos|openvms|fuchsia|hp-ux|serenityos)/i,
            // BeOS/OS2/AmigaOS/MorphOS/OpenVMS/Fuchsia/HP-UX/SerenityOS
            /(unix) ?([\w\.]*)/i
            // UNIX
          ],
          [a, b]
        ]
      }, Z = function(y, C) {
        if (typeof y === d && (C = y, y = r), !(this instanceof Z))
          return new Z(y, C).getResult();
        var x = typeof i !== h && i.navigator ? i.navigator : r, D = y || (x && x.userAgent ? x.userAgent : o), ae = x && x.userAgentData ? x.userAgentData : r, te = C ? W(ri, C) : ri, E = x && x.userAgent == D;
        return this.getBrowser = function() {
          var g = {};
          return g[a] = r, g[b] = r, je.call(g, D, te.browser), g[w] = lr(g[b]), E && x && x.brave && typeof x.brave.isBrave == f && (g[a] = "Brave"), g;
        }, this.getCPU = function() {
          var g = {};
          return g[$] = r, je.call(g, D, te.cpu), g;
        }, this.getDevice = function() {
          var g = {};
          return g[u] = r, g[s] = r, g[l] = r, je.call(g, D, te.device), E && !g[l] && ae && ae.mobile && (g[l] = _), E && g[s] == "Macintosh" && x && typeof x.standalone !== h && x.maxTouchPoints && x.maxTouchPoints > 2 && (g[s] = "iPad", g[l] = m), g;
        }, this.getEngine = function() {
          var g = {};
          return g[a] = r, g[b] = r, je.call(g, D, te.engine), g;
        }, this.getOS = function() {
          var g = {};
          return g[a] = r, g[b] = r, je.call(g, D, te.os), E && !g[a] && ae && ae.platform && ae.platform != "Unknown" && (g[a] = ae.platform.replace(/chrome os/i, L).replace(/macos/i, R)), g;
        }, this.getResult = function() {
          return {
            ua: this.getUA(),
            browser: this.getBrowser(),
            engine: this.getEngine(),
            os: this.getOS(),
            device: this.getDevice(),
            cpu: this.getCPU()
          };
        }, this.getUA = function() {
          return D;
        }, this.setUA = function(g) {
          return D = typeof g === p && g.length > ze ? Lt(g, ze) : g, this;
        }, this.setUA(D), this;
      };
      Z.VERSION = n, Z.BROWSER = X([a, b, w]), Z.CPU = X([$]), Z.DEVICE = X([s, u, l, P, _, A, m, O, de]), Z.ENGINE = Z.OS = X([a, b]), t.exports && (e = t.exports = Z), e.UAParser = Z;
      var Oe = typeof i !== h && (i.jQuery || i.Zepto);
      if (Oe && !Oe.ua) {
        var ot = new Z();
        Oe.ua = ot.getResult(), Oe.ua.get = function() {
          return ot.getUA();
        }, Oe.ua.set = function(y) {
          ot.setUA(y);
          var C = ot.getResult();
          for (var x in C)
            Oe.ua[x] = C[x];
        };
      }
    })(typeof window == "object" ? window : Tn);
  })(Ze, Ze.exports)), Ze.exports;
}
var $n = Rn();
const An = /* @__PURE__ */ Dn($n), On = new An(), sr = On.getResult(), Ln = (_a = sr.engine.name) == null ? void 0 : _a.toLowerCase(), vi = Number((_b = sr.engine.version) == null ? void 0 : _b.split(".")[0]), Bt = {
  "0x0001": "Escape",
  "0x0002": "Digit1",
  "0x0003": "Digit2",
  "0x0004": "Digit3",
  "0x0005": "Digit4",
  "0x0006": "Digit5",
  "0x0007": "Digit6",
  "0x0008": "Digit7",
  "0x0009": "Digit8",
  "0x000A": "Digit9",
  "0x000B": "Digit0",
  "0x000C": "Minus",
  "0x000D": "Equal",
  "0x000E": "Backspace",
  "0x000F": "Tab",
  "0x0010": "KeyQ",
  "0x0011": "KeyW",
  "0x0012": "KeyE",
  "0x0013": "KeyR",
  "0x0014": "KeyT",
  "0x0015": "KeyY",
  "0x0016": "KeyU",
  "0x0017": "KeyI",
  "0x0018": "KeyO",
  "0x0019": "KeyP",
  "0x001A": "BracketLeft",
  "0x001B": "BracketRight",
  "0x001C": "Enter",
  "0x001D": "ControlLeft",
  "0x001E": "KeyA",
  "0x001F": "KeyS",
  "0x0020": "KeyD",
  "0x0021": "KeyF",
  "0x0022": "KeyG",
  "0x0023": "KeyH",
  "0x0024": "KeyJ",
  "0x0025": "KeyK",
  "0x0026": "KeyL",
  "0x0027": "Semicolon",
  "0x0028": "Quote",
  "0x0029": "Backquote",
  "0x002A": "ShiftLeft",
  "0x002B": "Backslash",
  "0x002C": "KeyZ",
  "0x002D": "KeyX",
  "0x002E": "KeyC",
  "0x002F": "KeyV",
  "0x0030": "KeyB",
  "0x0031": "KeyN",
  "0x0032": "KeyM",
  "0x0033": "Comma",
  "0x0034": "Period",
  "0x0035": "Slash",
  "0x0036": "ShiftRight",
  "0x0037": "NumpadMultiply",
  "0x0038": "AltLeft",
  "0x0039": "Space",
  "0x003A": "CapsLock",
  "0x003B": "F1",
  "0x003C": "F2",
  "0x003D": "F3",
  "0x003E": "F4",
  "0x003F": "F5",
  "0x0040": "F6",
  "0x0041": "F7",
  "0x0042": "F8",
  "0x0043": "F9",
  "0x0044": "F10",
  "0x0045": "Pause",
  "0x0046": "ScrollLock",
  "0x0047": "Numpad7",
  "0x0048": "Numpad8",
  "0x0049": "Numpad9",
  "0x004A": "NumpadSubtract",
  "0x004B": "Numpad4",
  "0x004C": "Numpad5",
  "0x004D": "Numpad6",
  "0x004E": "NumpadAdd",
  "0x004F": "Numpad1",
  "0x0050": "Numpad2",
  "0x0051": "Numpad3",
  "0x0052": "Numpad0",
  "0x0053": "NumpadDecimal",
  "0x0056": "IntlBackslash",
  "0x0057": "F11",
  "0x0058": "F12",
  "0x0059": "NumpadEqual",
  "0x0064": "F13",
  "0x0065": "F14",
  "0x0066": "F15",
  "0x0067": "F16",
  "0x0068": "F17",
  "0x0069": "F18",
  "0x006A": "F19",
  "0x006B": "F20",
  "0x006C": "F21",
  "0x006D": "F22",
  "0x006E": "F23",
  "0x0070": "KanaMode",
  "0x0071": "Lang2",
  "0x0072": "Lang1",
  "0x0073": "IntlRo",
  "0x0076": "F24",
  "0x0079": "Convert",
  "0x007B": "NonConvert",
  "0x007D": "IntlYen",
  "0x007E": "NumpadComma",
  "0xE010": "MediaTrackPrevious",
  "0xE019": "MediaTrackNext",
  "0xE01C": "NumpadEnter",
  "0xE01D": "ControlRight",
  "0xE021": "LaunchApp2",
  "0xE022": "MediaPlayPause",
  "0xE024": "MediaStop",
  "0xE032": "BrowserHome",
  "0xE035": "NumpadDivide",
  "0xE037": "PrintScreen",
  "0xE038": "AltRight",
  "0xE045": "NumLock",
  "0xE046": "Pause",
  "0xE047": "Home",
  "0xE048": "ArrowUp",
  "0xE049": "PageUp",
  "0xE04B": "ArrowLeft",
  "0xE04D": "ArrowRight",
  "0xE04F": "End",
  "0xE050": "ArrowDown",
  "0xE051": "PageDown",
  "0xE052": "Insert",
  "0xE053": "Delete",
  "0xE05D": "ContextMenu",
  "0xE05E": "Power",
  "0xE065": "BrowserSearch",
  "0xE066": "BrowserFavorites",
  "0xE067": "BrowserRefresh",
  "0xE068": "BrowserStop",
  "0xE069": "BrowserForward",
  "0xE06A": "BrowserBack",
  "0xE06B": "LaunchApp1",
  "0xE06C": "LaunchMail",
  "0xE06D": "MediaSelect"
}, wi = {
  "0x0077": "Lang4",
  "0x0078": "Lang3",
  "0xE008": "Undo",
  "0xE00A": "Paste",
  "0xE017": "Cut",
  "0xE018": "Copy",
  "0xE020": "AudioVolumeMute",
  "0xE02C": "Eject",
  "0xE02E": "AudioVolumeDown",
  "0xE030": "AudioVolumeUp",
  "0xE03B": "Help",
  "0xE05B": "MetaLeft",
  "0xE05C": "MetaRight",
  "0xE05F": "Sleep",
  "0xE063": "WakeUp"
}, Mn = {
  "0x0054": "PrintScreen",
  "0xE020": "VolumeMute",
  // The documentation says it's 'AudioVolumeMute', but the actual test shows that it's 'VolumeMute'.
  "0xE02E": "VolumeDown",
  "0xE030": "VolumeUp",
  "0xE05B": vi > 117 ? "MetaLeft" : "OSLeft",
  "0xE05C": vi > 117 ? "MetaRight" : "OSRight"
}, Pn = {
  blink: zt({ ...Bt, ...wi }),
  gecko: zt({ ...Bt, ...Mn }),
  webkit: zt({ ...Bt, ...wi })
};
function zt(t) {
  const e = {};
  for (const [i, r] of Object.entries(t))
    e[r] = i;
  return e;
}
const mi = function(t) {
  const e = Pn[Ln];
  return parseInt(e[t], 16);
};
var Ht = /* @__PURE__ */ ((t) => (t.CTRL_LEFT = "ControlLeft", t.SHIFT_LEFT = "ShiftLeft", t.SHIFT_RIGHT = "ShiftRight", t.ALT_LEFT = "AltLeft", t.CTRL_RIGHT = "ControlRight", t.ALT_RIGHT = "AltRight", t.ControlLeft = "ControlLeft", t.ShiftLeft = "ShiftLeft", t.ShiftRight = "ShiftRight", t.AltLeft = "AltLeft", t.ControlRight = "ControlRight", t.AltRight = "AltRight", t))(Ht || {}), Fe = /* @__PURE__ */ ((t) => (t.CAPS_LOCK = "CapsLock", t.NUM_LOCK = "NumLock", t.SCROLL_LOCK = "ScrollLock", t.KANA_MODE = "KanaMode", t.CapsLock = "CapsLock", t.ScrollLock = "ScrollLock", t.NumLock = "NumLock", t.KanaMode = "KanaMode", t))(Fe || {}), ue = /* @__PURE__ */ ((t) => (t[t.CTRL_ALT_DEL = 0] = "CTRL_ALT_DEL", t[t.META = 1] = "META", t[t.CTRL_C = 2] = "CTRL_C", t[t.CTRL_V = 3] = "CTRL_V", t))(ue || {}), we = /* @__PURE__ */ ((t) => (t[t.Fit = 1] = "Fit", t[t.Full = 2] = "Full", t[t.Real = 3] = "Real", t))(we || {}), Qe = /* @__PURE__ */ ((t) => (t[t.Pixel = 0] = "Pixel", t[t.Line = 1] = "Line", t[t.Page = 2] = "Page", t))(Qe || {});
class Fn {
  constructor(e, i, r) {
    __publicField(this, "username");
    __publicField(this, "password");
    __publicField(this, "destination");
    __publicField(this, "proxyAddress");
    __publicField(this, "webSocketProtocols");
    __publicField(this, "serverDomain");
    __publicField(this, "authToken");
    __publicField(this, "desktopSize");
    __publicField(this, "extensions");
    this.username = e.username, this.password = e.password, this.proxyAddress = i.address, this.authToken = i.authToken, this.destination = r.destination, this.serverDomain = r.serverDomain, this.webSocketProtocols = r.webSocketProtocols ?? [], this.extensions = r.extensions, this.desktopSize = r.desktopSize;
  }
}
class Nn {
  /**
   * Creates a new ConfigBuilder instance.
   */
  constructor() {
    __publicField(this, "username", "");
    __publicField(this, "password", "");
    __publicField(this, "destination", "");
    __publicField(this, "proxyAddress", "");
    __publicField(this, "webSocketProtocols", []);
    __publicField(this, "serverDomain", "");
    __publicField(this, "authToken", "");
    __publicField(this, "desktopSize");
    __publicField(this, "extensions", []);
  }
  /**
   * Optional parameter
   *
   * @param username - The username to use for authentication
   * @returns The builder instance for method chaining
   */
  withUsername(e) {
    return this.username = e, this;
  }
  /**
   * Optional parameter
   *
   * @param password - The password for authentication
   * @returns The builder instance for method chaining
   */
  withPassword(e) {
    return this.password = e, this;
  }
  /**
   * Required parameter
   *
   * @param destination - The destination address to connect to
   * @returns The builder instance for method chaining
   */
  withDestination(e) {
    return this.destination = e, this;
  }
  /**
   * Required parameter
   *
   * @param proxyAddress - The address of the proxy server
   * @returns The builder instance for method chaining
   */
  withProxyAddress(e) {
    return this.proxyAddress = e, this;
  }
  /**
   * Optional parameter
   *
   * @param protocols - The WebSocket subprotocols offered during the opening handshake
   * @returns The builder instance for method chaining
   */
  withWebSocketProtocols(e) {
    return this.webSocketProtocols = [...e], this;
  }
  /**
   * Optional parameter
   *
   * @param serverDomain - The server domain to connect to
   * @returns The builder instance for method chaining
   */
  withServerDomain(e) {
    return this.serverDomain = e, this;
  }
  /**
   * Required parameter
   *
   * @param authToken - JWT token to connect to the proxy
   * @returns The builder instance for method chaining
   */
  withAuthToken(e) {
    return this.authToken = e, this;
  }
  /**
   * Optional parameter
   *
   * @param ext - The extension
   * @returns The builder instance for method chaining
   */
  withExtension(e) {
    return this.extensions.push(e), this;
  }
  /**
   * Optional
   *
   * @param desktopSize - The desktop size configuration object
   * @returns The builder instance for method chaining
   */
  withDesktopSize(e) {
    return this.desktopSize = e, this;
  }
  /**
   * Builds a new Config instance.
   *
   * @throws {Error} If required parameters (destination, proxyAddress, authToken) are not set
   * @returns A new Config instance with the configured values
   */
  build() {
    if (this.destination === "")
      throw new Error("destination has to be specified");
    if (this.proxyAddress === "")
      throw new Error("proxy address has to be specified");
    if (this.authToken === "")
      throw new Error("authentication token has to be specified");
    const e = { username: this.username, password: this.password }, i = { address: this.proxyAddress, authToken: this.authToken }, r = {
      destination: this.destination,
      serverDomain: this.serverDomain,
      webSocketProtocols: this.webSocketProtocols,
      extensions: this.extensions,
      desktopSize: this.desktopSize
    };
    return new Fn(e, i, r);
  }
}
class Pe {
  constructor() {
    __publicField(this, "subscribers");
    this.subscribers = [];
  }
  subscribe(e) {
    this.subscribers.push(e);
  }
  publish(e) {
    for (const i of this.subscribers)
      i(e);
  }
}
class Un {
  constructor(e) {
    __publicField(this, "module");
    __publicField(this, "canvas");
    __publicField(this, "keyboardUnicodeMode", false);
    __publicField(this, "backendSupportsUnicodeKeyboardShortcuts");
    __publicField(this, "onRemoteClipboardChanged");
    __publicField(this, "onForceClipboardUpdate");
    __publicField(this, "onCanvasResized");
    __publicField(this, "onWarningCallback");
    __publicField(this, "onClipboardRemoteUpdate");
    __publicField(this, "fileTransferProvider");
    __publicField(this, "cursorHasOverride", false);
    __publicField(this, "lastCursorStyle", "default");
    __publicField(this, "enableClipboard", true);
    __publicField(this, "_autoClipboard", true);
    __publicField(this, "sessionStartedObservable", new Pe());
    __publicField(this, "resizeObservable", new Pe());
    __publicField(this, "session");
    __publicField(this, "modifierKeyPressed", []);
    __publicField(this, "mousePositionObservable", new Pe());
    __publicField(this, "changeVisibilityObservable", new Pe());
    __publicField(this, "scaleObservable", new Pe());
    __publicField(this, "dynamicResizeObservable", new Pe());
    this.module = e, M.info("Web bridge initialized.");
  }
  get autoClipboard() {
    return this._autoClipboard;
  }
  // If set to false, the clipboard will not be enabled and the callbacks will not be registered to the Rust side
  setEnableClipboard(e) {
    this.enableClipboard = e;
  }
  // If set to true, automatic clipboard synchronization with the server is enabled.
  //
  // If set to false, then the client must invoke `PublicAPI.saveRemoteClipboardData` and
  // `PublicAPI.sendClipboardData` to write to clipboard and to send clipboard data to the server.
  setEnableAutoClipboard(e) {
    this._autoClipboard = e;
  }
  /// Callback to set the local clipboard content to data received from the remote.
  setOnRemoteClipboardChanged(e) {
    this.onRemoteClipboardChanged = e;
  }
  /// Callback which is called when the remote requests a forced clipboard update (e.g. on
  /// clipboard initialization sequence)
  setOnForceClipboardUpdate(e) {
    this.onForceClipboardUpdate = e;
  }
  /// Callback which is called when the canvas is resized.
  setOnCanvasResized(e) {
    this.onCanvasResized = e;
  }
  /// Callback which is called when the warning event is emitted.
  setOnWarningCallback(e) {
    this.onWarningCallback = e;
  }
  /// Callback which is called when the clipboard remote update event is emitted.
  setOnClipboardRemoteUpdate(e) {
    this.onClipboardRemoteUpdate = e;
  }
  /**
   * Enable file transfer support. Must be called before connect().
   * Implicitly enables clipboard (required for file transfer protocol).
   *
   * @param provider - Protocol-specific file transfer provider (e.g., RdpFileTransferProvider)
   * @returns The same provider, for chaining
   */
  enableFileTransfer(e) {
    var _a2;
    return (_a2 = this.fileTransferProvider) == null ? void 0 : _a2.dispose(), this.fileTransferProvider = e, this.enableClipboard = true, e;
  }
  mouseIn(e) {
    if (!this.session) return;
    this.syncModifier(e);
    const r = [
      [1, 0],
      // left button
      [2, 2],
      // right button
      [4, 1]
      // middle button
    ].filter(([n]) => (e.buttons & n) === 0).map(([, n]) => this.module.DeviceEvent.mouseButtonReleased(n));
    r.length > 0 && this.doTransactionFromDeviceEvents(r);
  }
  mouseOut(e) {
    this.releaseAllInputs();
  }
  focusLost() {
    this.releaseAllInputs();
  }
  sendKeyboardEvent(e) {
    this.sendKeyboard(e);
  }
  shutdown() {
    var _a2, _b2;
    (_a2 = this.fileTransferProvider) == null ? void 0 : _a2.dispose(), (_b2 = this.session) == null ? void 0 : _b2.shutdown();
  }
  mouseButtonState(e, i, r) {
    r && e.preventDefault();
    const n = i ? this.module.DeviceEvent.mouseButtonPressed : this.module.DeviceEvent.mouseButtonReleased;
    this.doTransactionFromDeviceEvents([n(e.button)]);
  }
  updateMousePosition(e) {
    this.doTransactionFromDeviceEvents([this.module.DeviceEvent.mouseMove(e.x, e.y)]), this.mousePositionObservable.publish(e);
  }
  configBuilder() {
    return new Nn();
  }
  async connect(e) {
    var _a2;
    const i = new this.module.SessionBuilder();
    if (i.proxyAddress(e.proxyAddress), i.webSocketProtocols(e.webSocketProtocols ?? []), i.destination(e.destination), i.serverDomain(e.serverDomain), i.password(e.password), i.authToken(e.authToken), i.username(e.username), i.renderCanvas(this.canvas), i.setCursorStyleCallbackContext(this), i.setCursorStyleCallback(this.setCursorStyleCallback), e.extensions.forEach((o) => {
      i.extension(o);
    }), this.onRemoteClipboardChanged != null && this.enableClipboard && i.remoteClipboardChangedCallback(this.onRemoteClipboardChanged), this.onForceClipboardUpdate != null && this.enableClipboard && i.forceClipboardUpdateCallback(this.onForceClipboardUpdate), this.fileTransferProvider != null && this.enableClipboard)
      for (const o of this.fileTransferProvider.getBuilderExtensions())
        i.extension(o);
    this.onCanvasResized != null && i.canvasResizedCallback(this.onCanvasResized), e.desktopSize != null && i.desktopSize(
      new this.module.DesktopSize(e.desktopSize.width, e.desktopSize.height)
    );
    const r = await i.connect();
    this.session = r, (_a2 = this.fileTransferProvider) == null ? void 0 : _a2.setSession(r), this.resizeObservable.publish({
      desktopSize: r.desktopSize(),
      sessionId: 0
    }), this.sessionStartedObservable.publish(null);
    const n = async () => {
      try {
        return M.info("Starting the session."), await r.run();
      } finally {
        this.setVisibility(false);
      }
    };
    return {
      sessionId: 0,
      initialDesktopSize: r.desktopSize(),
      websocketPort: 0,
      run: n
    };
  }
  sendSpecialCombination(e) {
    switch (e) {
      case ue.CTRL_ALT_DEL:
        this.ctrlAltDel();
        break;
      case ue.META:
        this.sendMeta();
        break;
      case ue.CTRL_C:
        this.sendCtrlC();
        break;
      case ue.CTRL_V:
        this.sendCtrlV();
        break;
    }
  }
  rotation_unit_from_wheel_event(e) {
    switch (e.deltaMode) {
      case e.DOM_DELTA_PIXEL:
        return Qe.Pixel;
      case e.DOM_DELTA_LINE:
        return Qe.Line;
      case e.DOM_DELTA_PAGE:
        return Qe.Page;
      default:
        return Qe.Pixel;
    }
  }
  mouseWheel(e) {
    const i = e.deltaY !== 0, r = i ? e.deltaY : e.deltaX, n = this.rotation_unit_from_wheel_event(e);
    this.doTransactionFromDeviceEvents([
      this.module.DeviceEvent.wheelRotations(i, -r, n)
    ]);
  }
  emitWarningEvent(e) {
    var _a2;
    (_a2 = this.onWarningCallback) == null ? void 0 : _a2.call(this, e);
  }
  emitClipboardRemoteUpdateEvent() {
    var _a2;
    (_a2 = this.onClipboardRemoteUpdate) == null ? void 0 : _a2.call(this);
  }
  setVisibility(e) {
    this.changeVisibilityObservable.publish(e);
  }
  setScale(e) {
    this.scaleObservable.publish(e);
  }
  setCanvas(e) {
    this.canvas = e;
  }
  resizeDynamic(e, i, r) {
    var _a2;
    this.dynamicResizeObservable.publish({ width: e, height: i }), (_a2 = this.session) == null ? void 0 : _a2.resize(e, i, r);
  }
  /// Triggered by the browser when local clipboard is updated. Clipboard backend should
  /// cache the content and send it to the server when it is requested.
  onClipboardChanged(e) {
    return (async () => {
      var _a2;
      await ((_a2 = this.session) == null ? void 0 : _a2.onClipboardPaste(e));
    })();
  }
  onClipboardChangedEmpty() {
    return (async () => {
      var _a2;
      await ((_a2 = this.session) == null ? void 0 : _a2.onClipboardPaste(new this.module.ClipboardData()));
    })();
  }
  setKeyboardUnicodeMode(e) {
    this.keyboardUnicodeMode = e;
  }
  setCursorStyleOverride(e) {
    e == null ? (this.canvas.style.cursor = this.lastCursorStyle, this.cursorHasOverride = false) : (this.canvas.style.cursor = e, this.cursorHasOverride = true);
  }
  invokeExtension(e) {
    var _a2;
    (_a2 = this.session) == null ? void 0 : _a2.invokeExtension(e);
  }
  releaseAllInputs() {
    var _a2;
    (_a2 = this.session) == null ? void 0 : _a2.releaseAllInputs();
  }
  supportsUnicodeKeyboardShortcuts() {
    var _a2, _b2;
    return this.backendSupportsUnicodeKeyboardShortcuts !== void 0 ? this.backendSupportsUnicodeKeyboardShortcuts : ((_a2 = this.session) == null ? void 0 : _a2.supportsUnicodeKeyboardShortcuts) ? (this.backendSupportsUnicodeKeyboardShortcuts = (_b2 = this.session) == null ? void 0 : _b2.supportsUnicodeKeyboardShortcuts(), this.backendSupportsUnicodeKeyboardShortcuts) : true;
  }
  sendKeyboard(e) {
    e.preventDefault();
    let i, r;
    e.type === "keydown" ? (i = this.module.DeviceEvent.keyPressed, r = this.module.DeviceEvent.unicodePressed) : e.type === "keyup" && (i = this.module.DeviceEvent.keyReleased, r = this.module.DeviceEvent.unicodeReleased);
    let n = true;
    if (!this.supportsUnicodeKeyboardShortcuts()) {
      for (const f of ["Alt", "Control", "Meta", "AltGraph", "OS"])
        if (e.getModifierState(f)) {
          n = false;
          break;
        }
    }
    const o = e.code in Ht, c = e.code in Fe;
    if (o && this.updateModifierKeyState(e), c && this.syncModifier(e), !e.repeat || !o && !c) {
      const f = mi(e.code), h = Number.isNaN(f);
      if (!this.keyboardUnicodeMode && i && !h) {
        this.doTransactionFromDeviceEvents([i(f)]);
        return;
      }
      if (this.keyboardUnicodeMode && r && i) {
        if (["Dead", "Unidentified"].indexOf(e.key) != -1)
          return;
        const d = mi(e.key);
        Number.isNaN(d) && e.key.length === 1 && !o && n ? this.doTransactionFromDeviceEvents([r(e.key)]) : h || this.doTransactionFromDeviceEvents([i(f)]);
        return;
      }
    }
  }
  setCursorStyleCallback(e, i, r, n) {
    let o;
    switch (e) {
      case "hidden": {
        o = "none";
        break;
      }
      case "default": {
        o = "default";
        break;
      }
      case "url": {
        if (i == null || r == null || n == null) {
          console.error("Invalid custom cursor parameters.");
          return;
        }
        const c = new Image();
        c.src = i;
        const f = Math.round(r), h = Math.round(n);
        o = `url(${i}) ${f} ${h}, default`;
        break;
      }
      default: {
        console.error(`Unsupported cursor style: ${e}.`);
        return;
      }
    }
    this.lastCursorStyle = o, this.cursorHasOverride || (this.canvas.style.cursor = o);
  }
  syncModifier(e) {
    var _a2;
    const i = e.getModifierState(Fe.CAPS_LOCK), r = e.getModifierState(Fe.NUM_LOCK), n = e.getModifierState(Fe.SCROLL_LOCK), o = e.getModifierState(Fe.KANA_MODE);
    (_a2 = this.session) == null ? void 0 : _a2.synchronizeLockKeys(
      n,
      r,
      i,
      o
    );
  }
  updateModifierKeyState(e) {
    const i = Ht[e.code];
    this.modifierKeyPressed.indexOf(i) === -1 ? this.modifierKeyPressed.push(i) : e.type === "keyup" && this.modifierKeyPressed.splice(this.modifierKeyPressed.indexOf(i), 1);
  }
  doTransactionFromDeviceEvents(e) {
    var _a2;
    const i = new this.module.InputTransaction();
    e.forEach((r) => i.addEvent(r)), (_a2 = this.session) == null ? void 0 : _a2.applyInputs(i);
  }
  ctrlAltDel() {
    const e = parseInt("0x001D", 16), i = parseInt("0x0038", 16), r = parseInt("0xE053", 16);
    this.doTransactionFromDeviceEvents([
      this.module.DeviceEvent.keyPressed(e),
      this.module.DeviceEvent.keyPressed(i),
      this.module.DeviceEvent.keyPressed(r),
      this.module.DeviceEvent.keyReleased(e),
      this.module.DeviceEvent.keyReleased(i),
      this.module.DeviceEvent.keyReleased(r)
    ]);
  }
  sendMeta() {
    const e = parseInt("0xE05B", 16);
    this.doTransactionFromDeviceEvents([
      this.module.DeviceEvent.keyPressed(e),
      this.module.DeviceEvent.keyReleased(e)
    ]);
  }
  sendCtrlC() {
    const e = parseInt("0x001D", 16), i = parseInt("0x002E", 16);
    this.doTransactionFromDeviceEvents([
      this.module.DeviceEvent.keyPressed(e),
      this.module.DeviceEvent.keyPressed(i),
      this.module.DeviceEvent.keyReleased(i),
      this.module.DeviceEvent.keyReleased(e)
    ]);
  }
  sendCtrlV() {
    const e = parseInt("0x001D", 16), i = parseInt("0x002F", 16);
    this.doTransactionFromDeviceEvents([
      this.module.DeviceEvent.keyPressed(e),
      this.module.DeviceEvent.keyPressed(i),
      this.module.DeviceEvent.keyReleased(i),
      this.module.DeviceEvent.keyReleased(e)
    ]);
  }
}
class Bn {
  constructor(e, i) {
    __publicField(this, "remoteDesktopService");
    __publicField(this, "clipboardService");
    this.remoteDesktopService = e, this.clipboardService = i;
  }
  configBuilder() {
    return this.remoteDesktopService.configBuilder();
  }
  connect(e) {
    return M.info("Initializing connection."), this.remoteDesktopService.connect(e);
  }
  ctrlAltDel() {
    this.remoteDesktopService.sendSpecialCombination(ue.CTRL_ALT_DEL);
  }
  metaKey() {
    this.remoteDesktopService.sendSpecialCombination(ue.META);
  }
  ctrlC() {
    this.remoteDesktopService.sendSpecialCombination(ue.CTRL_C);
  }
  ctrlV() {
    this.remoteDesktopService.sendSpecialCombination(ue.CTRL_V);
  }
  setVisibility(e) {
    M.info(`Change component visibility to: ${e}`), this.remoteDesktopService.setVisibility(e);
  }
  setScale(e) {
    this.remoteDesktopService.setScale(e);
  }
  shutdown() {
    this.remoteDesktopService.shutdown();
  }
  setKeyboardUnicodeMode(e) {
    this.remoteDesktopService.setKeyboardUnicodeMode(e);
  }
  setCursorStyleOverride(e) {
    this.remoteDesktopService.setCursorStyleOverride(e);
  }
  resize(e, i, r) {
    this.remoteDesktopService.resizeDynamic(e, i, r);
  }
  setEnableClipboard(e) {
    this.remoteDesktopService.setEnableClipboard(e);
  }
  setEnableAutoClipboard(e) {
    this.remoteDesktopService.setEnableAutoClipboard(e);
  }
  setOnWarningCallback(e) {
    this.remoteDesktopService.setOnWarningCallback(e);
  }
  setOnClipboardRemoteUpdateCallback(e) {
    this.remoteDesktopService.setOnClipboardRemoteUpdate(e);
  }
  async saveRemoteClipboardData() {
    return await this.clipboardService.saveRemoteClipboardData();
  }
  async sendClipboardData() {
    return await this.clipboardService.sendClipboardData();
  }
  invokeExtension(e) {
    this.remoteDesktopService.invokeExtension(e);
  }
  enableFileTransfer(e) {
    const i = e.onUploadStarted, r = e.onUploadFinished;
    return e.onUploadStarted = () => {
      i == null ? void 0 : i(), this.clipboardService.suppressMonitoring();
    }, e.onUploadFinished = () => {
      this.clipboardService.resumeMonitoring(), r == null ? void 0 : r();
    }, this.remoteDesktopService.enableFileTransfer(e);
  }
  getExposedFunctions() {
    return {
      setVisibility: this.setVisibility.bind(this),
      configBuilder: this.configBuilder.bind(this),
      connect: this.connect.bind(this),
      onWarningCallback: this.setOnWarningCallback.bind(this),
      onClipboardRemoteUpdateCallback: this.setOnClipboardRemoteUpdateCallback.bind(this),
      setScale: this.setScale.bind(this),
      ctrlAltDel: this.ctrlAltDel.bind(this),
      metaKey: this.metaKey.bind(this),
      ctrlC: this.ctrlC.bind(this),
      ctrlV: this.ctrlV.bind(this),
      shutdown: this.shutdown.bind(this),
      setKeyboardUnicodeMode: this.setKeyboardUnicodeMode.bind(this),
      setCursorStyleOverride: this.setCursorStyleOverride.bind(this),
      resize: this.resize.bind(this),
      setEnableClipboard: this.setEnableClipboard.bind(this),
      setEnableAutoClipboard: this.setEnableAutoClipboard.bind(this),
      saveRemoteClipboardData: this.saveRemoteClipboardData.bind(this),
      sendClipboardData: this.sendClipboardData.bind(this),
      invokeExtension: this.invokeExtension.bind(this),
      enableFileTransfer: this.enableFileTransfer.bind(this)
    };
  }
}
const jt = ir(false);
function zn() {
  const t = ir([]);
  return {
    subscribe: t.subscribe,
    enqueue(e) {
      t.update((i) => [...i, e]);
    },
    shift() {
      let e;
      return t.update((i) => i.length == 0 ? i : (e = i[0], i.slice(1))), e;
    },
    length() {
      return rr(t).length;
    }
  };
}
const Gt = zn();
var K = /* @__PURE__ */ ((t) => (t[t.Full = 0] = "Full", t[t.TextOnly = 1] = "TextOnly", t[t.TextOnlyServerOnly = 2] = "TextOnlyServerOnly", t[t.None = 3] = "None", t))(K || {}), or = /* @__PURE__ */ ((t) => (t[t.General = 0] = "General", t[t.WrongPassword = 1] = "WrongPassword", t[t.LogonFailure = 2] = "LogonFailure", t[t.AccessDenied = 3] = "AccessDenied", t[t.RDCleanPath = 4] = "RDCleanPath", t[t.ProxyConnect = 5] = "ProxyConnect", t[t.NegotiationFailure = 6] = "NegotiationFailure", t))(or || {});
const In = 100;
function re(t) {
  throw {
    kind: () => or.General,
    backtrace: () => t
  };
}
class Wn {
  constructor(e, i) {
    __publicField(this, "remoteDesktopService");
    __publicField(this, "module");
    __publicField(this, "ClipboardApiSupported", K.None);
    __publicField(this, "lastClientClipboardItems", {});
    __publicField(this, "lastReceivedClipboardData", {});
    __publicField(this, "lastSentClipboardData", null);
    __publicField(this, "clipboardDataToSave", null);
    __publicField(this, "lastClipboardMonitorLoopError", null);
    // When true, the clipboard monitoring loop skips reading/sending clipboard updates.
    // Used to prevent the monitoring loop from clobbering an active file upload's
    // FormatList with a text/image clipboard update.
    __publicField(this, "monitoringSuppressed", false);
    // Firefox v126 and below does not support `navigator.clipboard.read` and `navigator.clipboard.write`.
    // So, we need to define specific methods to handle text-only clipboard.
    //
    // Also, Firefox v124 and below does not support `navigator.clipboard.readText`.
    // Because of this, we cannot read the data from the clipboard at all.
    __publicField(this, "ffClipboardDataToSave", null);
    this.remoteDesktopService = e, this.module = i;
  }
  /**
   * Suppress clipboard monitoring. While suppressed, the 100ms monitoring
   * loop will skip reading the local clipboard and sending updates to the
   * remote. This prevents the monitor from clobbering a file upload's
   * FormatList announcement with a text/image clipboard update.
   */
  suppressMonitoring() {
    this.monitoringSuppressed = true;
  }
  /**
   * Resume clipboard monitoring after a previous {@link suppressMonitoring} call.
   */
  resumeMonitoring() {
    this.monitoringSuppressed = false;
  }
  async initClipboard() {
    if (!window.isSecureContext) {
      this.remoteDesktopService.emitWarningEvent("Clipboard is available only in secure contexts (HTTPS).");
      return;
    }
    if (navigator.clipboard != null && (navigator.clipboard.read != null && navigator.clipboard.write != null ? this.ClipboardApiSupported = K.Full : navigator.clipboard.readText != null ? (this.ClipboardApiSupported = K.TextOnly, this.remoteDesktopService.emitWarningEvent(
      "Clipboard is limited to text-only data types due to an outdated browser version!"
    )) : navigator.clipboard.writeText != null && (this.ClipboardApiSupported = K.TextOnlyServerOnly, this.remoteDesktopService.emitWarningEvent(
      "Clipboard reading is not supported and writing is limited to text-only data types due to an outdated browser version!"
    ))), this.ClipboardApiSupported === K.Full)
      try {
        (await navigator.permissions.query({
          name: "clipboard-read"
        })).state === "denied" && (this.ClipboardApiSupported = K.TextOnly);
      } catch {
        try {
          await navigator.clipboard.read();
        } catch {
          this.ClipboardApiSupported = K.TextOnly;
        }
      }
    if (this.ClipboardApiSupported === K.None) {
      this.remoteDesktopService.emitWarningEvent(
        "Clipboard is not supported due to an outdated browser version!"
      );
      return;
    }
    this.remoteDesktopService.setOnForceClipboardUpdate(this.onForceClipboardUpdate.bind(this)), this.ClipboardApiSupported === K.Full ? this.remoteDesktopService.autoClipboard ? (this.remoteDesktopService.setOnRemoteClipboardChanged(this.onRemoteClipboardChangedAutoMode.bind(this)), this.remoteDesktopService.sessionStartedObservable.subscribe((e) => {
      this.scheduleOnMonitorClipboardUpdate();
    })) : this.remoteDesktopService.setOnRemoteClipboardChanged(
      this.onRemoteClipboardChangedManualMode.bind(this)
    ) : this.remoteDesktopService.setOnRemoteClipboardChanged(this.ffOnRemoteClipboardChanged.bind(this));
  }
  // Copies clipboard content received from the server to the local clipboard.
  // Returns the result of the operation. On failure, it additionally raises an error session event.
  async saveRemoteClipboardData() {
    if (this.ClipboardApiSupported !== K.Full)
      return await this.ffSaveRemoteClipboardData();
    this.clipboardDataToSave == null && re("The server did not send the clipboard data.");
    try {
      const e = this.clipboardDataToRecord(this.clipboardDataToSave), i = new ClipboardItem(e);
      await navigator.clipboard.write([i]), this.clipboardDataToSave = null;
    } catch (e) {
      re("Failed to write to the clipboard: " + e);
    }
  }
  // Sends local clipboard's content to the server.
  // Returns the result of the operation. On failure, it additionally raises an error session event.
  async sendClipboardData() {
    if (this.ClipboardApiSupported !== K.Full)
      return await this.ffSendClipboardData();
    const e = await navigator.clipboard.read().catch((n) => {
      re("Failed to read from the clipboard: " + n);
    });
    e.length == 0 && re("The clipboard has no data.");
    const i = e[0];
    i.types.some((n) => n.startsWith("text/") || n.startsWith("image/png")) || re("The clipboard has no data of supported type (text or image).");
    const r = new this.module.ClipboardData();
    for (const n of i.types) {
      const o = n.startsWith("text/"), c = await i.getType(n);
      o ? r.addText(n, await c.text()) : r.addBinary(n, new Uint8Array(await c.arrayBuffer()));
    }
    r.isEmpty() || (this.lastSentClipboardData = r, await this.remoteDesktopService.onClipboardChanged(r));
  }
  scheduleOnMonitorClipboardUpdate() {
    setTimeout(this.onMonitorClipboard.bind(this), In);
  }
  runWhenWindowFocused(e) {
    document.hasFocus() ? e() : Gt.enqueue(e);
  }
  // This function is required to convert `ClipboardData` to an object that can be used
  // with `ClipboardItem` API.
  clipboardDataToRecord(e) {
    const i = {};
    for (const r of e.items()) {
      const n = r.mimeType();
      i[n] = new Blob([r.value()], { type: n });
    }
    return i;
  }
  clipboardDataToClipboardItemsRecord(e) {
    const i = {};
    for (const r of e.items()) {
      const n = r.mimeType();
      i[n] = r.value();
    }
    return i;
  }
  // This callback is required to send initial clipboard state if available.
  onForceClipboardUpdate() {
    try {
      this.lastSentClipboardData ? this.remoteDesktopService.onClipboardChanged(this.lastSentClipboardData) : this.remoteDesktopService.onClipboardChangedEmpty();
    } catch (e) {
      console.error("Failed to send initial clipboard state: " + e);
    }
  }
  // This callback is required to update client clipboard state when remote side has changed.
  onRemoteClipboardChangedManualMode(e) {
    this.clipboardDataToSave = e, this.remoteDesktopService.emitClipboardRemoteUpdateEvent();
  }
  // This callback is required to update client clipboard state when remote side has changed.
  onRemoteClipboardChangedAutoMode(e) {
    try {
      const i = this.clipboardDataToRecord(e), r = new ClipboardItem(i);
      this.runWhenWindowFocused(() => {
        this.lastReceivedClipboardData = this.clipboardDataToClipboardItemsRecord(e), navigator.clipboard.write([r]);
      });
    } catch (i) {
      console.error("Failed to set client clipboard: " + i);
    }
  }
  // Called periodically to monitor clipboard changes
  async onMonitorClipboard() {
    let e = false;
    try {
      if (this.monitoringSuppressed || !document.hasFocus())
        return;
      const i = await navigator.clipboard.read();
      if (i.length == 0)
        return;
      const r = i[0];
      if (!r.types.some((c) => c.startsWith("text/") || c.startsWith("image/png")))
        return;
      const n = {};
      let o = true;
      for (const c of r.types) {
        const f = c.startsWith("text/"), h = await r.getType(c), d = f ? await h.text() : new Uint8Array(await h.arrayBuffer()), p = f ? function(s, a) {
          return s === a;
        } : function(s, a) {
          return !(s instanceof Uint8Array) || !(a instanceof Uint8Array) ? false : s.length === a.length && s.every((l, u) => l === a[u]);
        }, w = this.lastClientClipboardItems[c];
        p(w, d) || (p(this.lastReceivedClipboardData[c], d) ? this.lastClientClipboardItems[c] = this.lastReceivedClipboardData[c] : o = false), n[c] = d;
      }
      if (!o) {
        this.lastClientClipboardItems = n;
        const c = new this.module.ClipboardData();
        Object.entries(n).forEach(([f, h]) => {
          h != null && (f.startsWith("text/") && typeof h == "string" ? c.addText(f, h) : f.startsWith("image/") && h instanceof Uint8Array && c.addBinary(f, h));
        }), c.isEmpty() || (this.lastSentClipboardData = c, await this.remoteDesktopService.onClipboardChanged(c));
      }
    } catch (i) {
      if (i instanceof DOMException && i.name === "NotAllowedError") {
        console.warn("Clipboard monitoring disabled: browser requires user activation for clipboard read."), this.remoteDesktopService.setOnRemoteClipboardChanged(
          this.onRemoteClipboardChangedManualMode.bind(this)
        ), e = true;
        return;
      }
      i instanceof Error && ((this.lastClipboardMonitorLoopError === null || this.lastClipboardMonitorLoopError.toString() !== i.toString()) && console.error("Clipboard monitoring error: " + i), this.lastClipboardMonitorLoopError = i);
    } finally {
      !e && !rr(jt) && this.scheduleOnMonitorClipboardUpdate();
    }
  }
  // This function is required to retrieve the text data from the `ClipboardData`.
  ffRetrieveTextData(e) {
    for (const i of e.items())
      if (i.mimeType().startsWith("text/")) {
        const r = i.value();
        if (typeof r == "string") return r;
      }
    return "";
  }
  // Firefox specific function.
  // This callback is required to update client clipboard state when remote side has changed.
  ffOnRemoteClipboardChanged(e) {
    const i = this.ffRetrieveTextData(e);
    i !== "" && (this.ffClipboardDataToSave = i, this.remoteDesktopService.emitClipboardRemoteUpdateEvent());
  }
  // Firefox specific function. We are using text-only clipboard API here.
  //
  // Copies clipboard content received from the server to the local clipboard.
  // Returns the result of the operation. On failure, it additionally raises an error session event.
  async ffSaveRemoteClipboardData() {
    this.ffClipboardDataToSave == null && re("The server did not send the clipboard data.");
    try {
      await navigator.clipboard.writeText(this.ffClipboardDataToSave), this.ffClipboardDataToSave = null;
    } catch (e) {
      re("Failed to write to the clipboard: " + e);
    }
  }
  // Firefox specific function. We are using text-only clipboard API here.
  //
  // Sends local clipboard's content to the server.
  // Returns the result of the operation. On failure, it additionally raises an error session event.
  async ffSendClipboardData() {
    this.ClipboardApiSupported !== K.TextOnly && re("The browser does not support clipboard read.");
    const e = await navigator.clipboard.readText().catch((r) => {
      re("Failed to read from the clipboard: " + r);
    });
    e.length == 0 && re("The clipboard has no data.");
    const i = new this.module.ClipboardData();
    i.addText("text/plain", e), i.isEmpty() || (this.lastSentClipboardData = i, await this.remoteDesktopService.onClipboardChanged(i));
  }
}
var Vn = (t, e) => e(t, true), Kn = (t, e) => e(t, false), qn = (t) => t.preventDefault(), Hn = /* @__PURE__ */ hn('<div class="svelte-1103xra"><div><div class="screen-viewer svelte-1103xra"><canvas id="renderer" tabindex="0" class="svelte-1103xra"></canvas></div></div></div>');
const jn = {
  hash: "svelte-1103xra",
  code: ".screen-wrapper.svelte-1103xra {position:relative;}.capturing-inputs.svelte-1103xra {outline:1px solid rgba(0, 97, 166, 0.7);outline-offset:-1px;}canvas.svelte-1103xra {width:100%;height:100%;}.svelte-1103xra::selection {background-color:transparent;}.screen-wrapper.hidden.svelte-1103xra {pointer-events:none !important;position:absolute !important;visibility:hidden;height:100%;width:100%;transform:translate(-100%, -100%);}"
};
function ar(t, e) {
  Gi(e, true), vn(t, jn);
  let i = ut(e, "scale"), r = ut(e, "verbose"), n = ut(e, "flexcenter"), o = ut(e, "module"), c = Pt(false), f = () => {
    var _a2, _b2;
    return M.info(`
            capturingInputs: ${document.activeElement === p}
            current active element: ${document.activeElement}
        `), ((_b2 = (_a2 = document.activeElement) == null ? void 0 : _a2.shadowRoot) == null ? void 0 : _b2.firstElementChild) === h;
  }, h, d, p, w = Pt(""), s = Pt(""), a = new Un(o()), l = new Wn(a, o()), u = new Bn(a, l), b = we.Fit;
  function $(v) {
    f() && Ot(v);
  }
  function P() {
    ze(), De(), window.addEventListener("keydown", $, false), window.addEventListener("keyup", $, false), window.addEventListener("focus", Ae), window.addEventListener("blur", Ve), document.addEventListener("visibilitychange", pe);
  }
  function _() {
    n() === "true" && (h.style.flexGrow = "", h.style.display = "", h.style.justifyContent = "", h.style.alignItems = "");
  }
  function m(v) {
    n() === "true" && (h.style.flexGrow = "1", h.style.display = "flex", h.style.justifyContent = "center", h.style.alignItems = "center");
  }
  function A(v, S, L) {
    let R = `height: ${v}; width: ${S}`;
    R = `${R}; max-height: ${v}; max-width: ${S}; min-height: ${v}; min-width: ${S}`, H(w, ke(R));
  }
  function O(v, S, L) {
    H(s, `height: ${v}; width: ${S}; overflow: ${L}`);
  }
  const de = (v) => {
    he(i());
  };
  function ze() {
    a.resizeObservable.subscribe((v) => {
      M.info(`Resize canvas to: ${v.desktopSize.width}x${v.desktopSize.height}`), p.width = v.desktopSize.width, p.height = v.desktopSize.height, he(i());
    });
  }
  function De() {
    window.addEventListener("resize", de), a.scaleObservable.subscribe((v) => {
      M.info("Change scale!"), he(v);
    }), a.dynamicResizeObservable.subscribe((v) => {
      M.info(`Dynamic resize!, width: ${v.width}, height: ${v.height}`), A(v.height.toString() + "px", v.width.toString() + "px");
    }), a.changeVisibilityObservable.subscribe((v) => {
      H(c, ke(v)), v && (O("100%", "100%", "hidden"), setTimeout(() => he(i()), 150));
    });
  }
  function fe() {
    he(b);
  }
  function he(v) {
    if (_(), U(c))
      switch (v) {
        case "fit":
        case we.Fit:
          M.info("Size to fit"), b = we.Fit, i("fit"), Te();
          break;
        case "full":
        case we.Full:
          M.info("Size to full"), b = we.Full, rt(), i("full");
          break;
        case "real":
        case we.Real:
          M.info("Size to real"), b = we.Real, Re(), i("real");
          break;
      }
  }
  function rt() {
    const v = be(), S = v.x, L = v.y;
    let R = p.width, F = p.height;
    const W = Math.min(S / p.width, L / p.height);
    R = R * W, F = F * W, O(`${L}px`, `${S}px`, "hidden"), R = R > 0 ? R : 0, F = F > 0 ? F : 0, A(`${F}px`, `${R}px`);
  }
  function Te(v = false) {
    const S = be(), L = d.getBoundingClientRect(), R = S.x - L.x, F = S.y - L.y;
    let W = p.width, X = p.height;
    if (!v || R < p.width || F < p.height) {
      const qe = Math.min(R / p.width, F / p.height);
      W = W * qe, X = X * qe;
    }
    W = W > 0 ? W : 0, X = X > 0 ? X : 0, O("initial", "initial", "hidden"), A(`${X}px`, `${W}px`), m();
  }
  function Re() {
    const v = be(), S = d.getBoundingClientRect(), L = v.x - S.x, R = v.y - S.y;
    L < p.width || R < p.height ? O(`${Math.min(R, p.height)}px`, `${Math.min(L, p.width)}px`, "auto") : O("initial", "initial", "initial"), A(`${p.height}px`, `${p.width}px`), m();
  }
  function At(v) {
    const S = p == null ? void 0 : p.getBoundingClientRect(), L = (p == null ? void 0 : p.width) / S.width, R = (p == null ? void 0 : p.height) / S.height, F = {
      x: Math.round((v.clientX - S.left) * L),
      y: Math.round((v.clientY - S.top) * R)
    };
    a.updateMousePosition(F);
  }
  function Ee(v, S) {
    a.mouseButtonState(v, S, true);
  }
  function $e(v) {
    a.mouseWheel(v);
  }
  function nt(v) {
    p.focus({ preventScroll: true }), a.mouseIn(v);
  }
  function st(v) {
    a.mouseOut(v);
  }
  function Ot(v) {
    return a.sendKeyboardEvent(v), true;
  }
  function be() {
    const v = window, S = document, L = S.documentElement, R = S.getElementsByTagName("body")[0], F = v.innerWidth ?? L.clientWidth ?? R.clientWidth, W = v.innerHeight ?? L.clientHeight ?? R.clientHeight;
    return { x: F, y: W };
  }
  async function Ie() {
    M.info("Start canvas initialization..."), p.width = 800, p.height = 600, a.setCanvas(p), a.setOnCanvasResized(fe), P();
  }
  function We() {
    let v = {
      irgUserInteraction: u.getExposedFunctions()
    };
    M.info("Component ready"), M.info("Dispatching ready event"), h.dispatchEvent(new CustomEvent("ready", {
      detail: v,
      bubbles: true,
      composed: true
    }));
  }
  function Ae() {
    var _a2;
    try {
      for (; Gt.length() > 0; )
        (_a2 = Gt.shift()) == null ? void 0 : _a2();
    } catch (v) {
      console.error("Failed to run the function queued for execution when the window received focus: " + v);
    }
  }
  function Ve() {
    a.focusLost();
  }
  function pe() {
    document.visibilityState === "hidden" && a.focusLost();
  }
  tr(async () => {
    jt.set(false), M.verbose = r() === "true", M.info("Dom ready"), await Ie();
    try {
      await l.initClipboard();
    } catch (v) {
      M.error("Clipboard initialization failed: " + v);
    }
    We();
  }), _n(() => {
    window.removeEventListener("resize", de), window.removeEventListener("keydown", $, false), window.removeEventListener("keyup", $, false), window.removeEventListener("focus", Ae), window.removeEventListener("blur", Ve), document.removeEventListener("visibilitychange", pe), jt.set(true);
  });
  var ve = Hn(), Y = Nt(ve);
  let Ke;
  var oe = Nt(Y), I = Nt(oe);
  return I.__mousemove = At, I.__mousedown = [Vn, Ee], I.__mouseup = [Kn, Ee], I.__contextmenu = [qn], Ut(I, (v) => p = v, () => p), Ft(oe), Ft(Y), Ut(Y, (v) => d = v, () => d), Ft(ve), Ut(ve, (v) => h = v, () => h), en(() => {
    Ke = mn(Y, 1, `screen-wrapper scale-${i() ?? ""}`, "svelte-1103xra", Ke, {
      hidden: !U(c),
      "capturing-inputs": f
    }), fi(Y, "style", U(s)), fi(oe, "style", U(w));
  }), lt("mouseleave", I, (v) => {
    st(v);
  }), lt("mouseenter", I, (v) => {
    nt(v);
  }), lt("wheel", I, $e), lt("selectstart", I, (v) => {
    v.preventDefault();
  }), Qi(t, ve), Yi({
    get scale() {
      return i();
    },
    set scale(v) {
      i(v), Ye();
    },
    get verbose() {
      return r();
    },
    set verbose(v) {
      r(v), Ye();
    },
    get flexcenter() {
      return n();
    },
    set flexcenter(v) {
      n(v), Ye();
    },
    get module() {
      return o();
    },
    set module(v) {
      o(v), Ye();
    }
  });
}
dn([
  "mousemove",
  "mousedown",
  "mouseup",
  "contextmenu"
]);
customElements.define("iron-remote-desktop", kn(
  ar,
  {
    scale: {},
    verbose: {},
    flexcenter: {},
    module: {}
  },
  [],
  [],
  false,
  (t) => class extends t {
    constructor() {
      super(), this.attachShadow({ mode: "open", delegatesFocus: true });
    }
  }
));
const Gn = /* @__PURE__ */ Object.freeze(/* @__PURE__ */ Object.defineProperty({
  __proto__: null,
  default: ar
}, Symbol.toStringTag, { value: "Module" }));
export {
  Fn as Config,
  Nn as ConfigBuilder,
  Gn as default
};
