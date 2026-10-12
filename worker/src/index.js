// API del Amigo Invisible (Cloudflare Worker + D1)
// - Cada participante reclama su nombre con un PIN y escribe su carta de deseos.
// - El sorteo lo hace el Worker y guarda el resultado CIFRADO con la clave pública de cada uno:
//   solo quien conoce el PIN puede leer a quién le ha tocado. Ni el organizador lo ve.

const MISSIONS = [
  "El regalo tiene que llevar algo de color rojo.",
  "Envuélvelo con papel de periódico.",
  "Mete dentro una nota escrita a mano con un recuerdo vuestro.",
  "Una parte del regalo tiene que estar hecha por ti.",
  "Tiene que incluir algo que se pueda comer.",
  "Mete el regalo dentro de otra caja que despiste.",
  "Escribe la tarjeta en verso, con rima.",
  "Que lleve algo de Casarabonela o de Málaga.",
  "El envoltorio tiene que ser lo más ridículo posible.",
  "Que tenga que ver con una canción que le guste.",
  "Incluye algo que le recuerde a cuando erais pequeños.",
  "Firma la tarjeta con un nombre en clave, nunca con el tuyo.",
  "Escóndele una pista falsa para que crea que eres otro."
];
const MAX_CARTA = 900_000;      // bytes de JSON por carta (fotos incluidas)
const MAX_FAILS = 8, LOCK_MS = 10 * 60_000;

const json = (data, status = 200) => new Response(JSON.stringify(data), {
  status, headers: { "content-type": "application/json; charset=utf-8", ...CORS }
});
const CORS = {
  "access-control-allow-origin": "*",
  "access-control-allow-methods": "GET,POST,OPTIONS",
  "access-control-allow-headers": "content-type,authorization",
  "access-control-max-age": "86400"
};
const err = (msg, status = 400) => json({ error: msg }, status);

const enc = new TextEncoder();
const b64 = buf => btoa(String.fromCharCode(...new Uint8Array(buf)));
const unb64 = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));
const rnd = n => crypto.getRandomValues(new Uint32Array(1))[0] % n;
const shuffle = a => { a = a.slice(); for (let i = a.length - 1; i > 0; i--) { const j = rnd(i + 1); [a[i], a[j]] = [a[j], a[i]] } return a };

async function hashPin(pin, salt, pepper) {
  const d = await crypto.subtle.digest("SHA-256", enc.encode(`${salt}:${pin}:${pepper}`));
  return b64(d);
}
function safeEq(a, b) {
  if (typeof a !== "string" || typeof b !== "string" || a.length !== b.length) return false;
  let r = 0; for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i); return r === 0;
}

async function getCfg(env) {
  const r = await env.DB.prepare("SELECT v FROM kv WHERE k='cfg'").first();
  return r ? JSON.parse(r.v) : { event: "Amigo Invisible 2026", budget: "20", date: "2026-12-24", missions: true, excl: [] };
}
async function isDrawn(env) {
  const r = await env.DB.prepare("SELECT v FROM kv WHERE k='drawn'").first();
  return r ? r.v === "1" : false;
}
// Fecha de hoy en España (YYYY-MM-DD). El Día D se cuenta en hora de Madrid.
const todayMadrid = () => new Intl.DateTimeFormat("en-CA", { timeZone: "Europe/Madrid", year: "numeric", month: "2-digit", day: "2-digit" }).format(new Date());
// Sellado: con el sorteo hecho y el Día D ya llegado, el resultado no se puede deshacer ni repetir, y la fecha no se puede mover.
const isSealed = (cfg, drawn) => drawn && !!cfg.date && todayMadrid() >= cfg.date;
const people = env => env.DB.prepare("SELECT * FROM people ORDER BY pos, name").all().then(r => r.results);

function cleanCarta(c) {
  const s = v => String(v ?? "").slice(0, 200).trim();
  const url = v => { v = s(v); if (!v) return ""; try { const u = new URL(v); return /^https?:$/.test(u.protocol) ? u.href : "" } catch { return "" } };
  const img = v => (typeof v === "string" && /^data:image\/(webp|jpeg|png);base64,[A-Za-z0-9+/=]+$/.test(v) && v.length < 200_000) ? v : url(v);
  const f = (c && c.f) || {};
  return {
    f: { w1: s(f.w1), w2: s(f.w2), w3: s(f.w3), w4: s(f.w4).slice(0, 30) },
    it: (Array.isArray(c && c.it) ? c.it : []).slice(0, 20)
      .map(x => ({ t: s(x.t).slice(0, 80), u: url(x.u), p: s(x.p).replace(/[^\d.,]/g, "").slice(0, 8), n: s(x.n).slice(0, 120), i: img(x.i) }))
      .filter(x => x.t)
  };
}

// Autentica a un participante por nombre + PIN, con bloqueo tras varios fallos
async function auth(env, name, pin) {
  const p = await env.DB.prepare("SELECT * FROM people WHERE name=?").bind(String(name || "")).first();
  if (!p) return [null, err("Ese nombre no está en la lista.", 404)];
  if (!p.pin_hash) return [null, err("Este agente todavía no se ha registrado.", 409)];
  const now = Date.now();
  if (p.lock_until > now) return [null, err(`Demasiados intentos. Espera ${Math.ceil((p.lock_until - now) / 60000)} min.`, 429)];
  const h = await hashPin(String(pin || ""), p.salt, env.PEPPER);
  if (!safeEq(h, p.pin_hash)) {
    const fails = p.fails + 1;
    await env.DB.prepare("UPDATE people SET fails=?, lock_until=? WHERE name=?")
      .bind(fails >= MAX_FAILS ? 0 : fails, fails >= MAX_FAILS ? now + LOCK_MS : 0, p.name).run();
    return [null, err("PIN incorrecto.", 401)];
  }
  if (p.fails) await env.DB.prepare("UPDATE people SET fails=0 WHERE name=?").bind(p.name).run();
  return [p, null];
}

function publicPeople(list) {
  return list.map(p => {
    let items = 0; try { items = JSON.parse(p.carta || "{}").it?.length || 0 } catch {}
    return { name: p.name, joined: !!p.pin_hash, items, updated: p.updated || 0 };
  });
}

// Sorteo: nadie se toca a sí mismo y se respetan las parejas vetadas
function derange(names, excl) {
  const ban = new Set(); (excl || []).forEach(([a, b]) => { ban.add(a + "|" + b); ban.add(b + "|" + a) });
  for (let t = 0; t < 5000; t++) {
    const r = shuffle(names);
    if (names.every((g, i) => g !== r[i] && !ban.has(g + "|" + r[i]))) return names.map((g, i) => [g, r[i]]);
  }
  return null;
}

async function encryptFor(pubB64, obj) {
  const key = await crypto.subtle.importKey("spki", unb64(pubB64), { name: "RSA-OAEP", hash: "SHA-256" }, false, ["encrypt"]);
  return b64(await crypto.subtle.encrypt({ name: "RSA-OAEP" }, key, enc.encode(JSON.stringify(obj))));
}

export default {
  async fetch(req, env) {
    if (req.method === "OPTIONS") return new Response(null, { headers: CORS });
    const url = new URL(req.url), path = url.pathname.replace(/\/+$/, "");
    let body = {};
    if (req.method === "POST") {
      const len = +req.headers.get("content-length") || 0;
      if (len > 1_500_000) return err("Demasiado grande. Usa menos fotos o más pequeñas.", 413);
      try { body = await req.json() } catch { return err("Petición mal formada.") }
    }
    try {
      // ---------- Público ----------
      if (path === "/api/state" && req.method === "GET") {
        const [cfg, drawn, list] = await Promise.all([getCfg(env), isDrawn(env), people(env)]);
        return json({ cfg: { event: cfg.event, budget: cfg.budget, date: cfg.date, missions: cfg.missions }, drawn, sealed: isSealed(cfg, drawn), people: publicPeople(list) });
      }

      if (path === "/api/claim" && req.method === "POST") {
        const { name, pin, pub, wrapped } = body;
        if (!/^\d{4,6}$/.test(String(pin || ""))) return err("El PIN tiene que ser de 4 a 6 números.");
        if (typeof pub !== "string" || pub.length > 1000 || typeof wrapped !== "string" || wrapped.length > 5000) return err("Faltan las claves.");
        if (await isDrawn(env)) return err("El sorteo ya se hizo. Habla con el organizador.", 409);
        const salt = b64(crypto.getRandomValues(new Uint8Array(12)));
        const h = await hashPin(String(pin), salt, env.PEPPER);
        const r = await env.DB.prepare("UPDATE people SET pin_hash=?, salt=?, pub=?, wrapped=?, fails=0, lock_until=0 WHERE name=? AND pin_hash IS NULL")
          .bind(h, salt, pub, wrapped, String(name || "")).run();
        if (!r.meta.changes) return err("Ese nombre ya está registrado o no existe.", 409);
        return json({ ok: true });
      }

      if (path === "/api/login" && req.method === "POST") {
        const [p, e] = await auth(env, body.name, body.pin); if (e) return e;
        const [cfg, drawn] = await Promise.all([getCfg(env), isDrawn(env)]);
        return json({ name: p.name, wrapped: p.wrapped, carta: JSON.parse(p.carta || '{"f":{},"it":[]}'), assignment: drawn ? p.assignment : null, drawn,
          cfg: { event: cfg.event, budget: cfg.budget, date: cfg.date } });
      }

      if (path === "/api/carta" && req.method === "POST") {
        const [p, e] = await auth(env, body.name, body.pin); if (e) return e;
        const c = JSON.stringify(cleanCarta(body.carta));
        if (c.length > MAX_CARTA) return err("La carta pesa demasiado. Quita alguna foto subida o usa enlaces de imagen.", 413);
        await env.DB.prepare("UPDATE people SET carta=?, updated=? WHERE name=?").bind(c, Date.now(), p.name).run();
        return json({ ok: true, updated: Date.now() });
      }

      if (path === "/api/carta/of" && req.method === "POST") {
        const [, e] = await auth(env, body.name, body.pin); if (e) return e;
        const t = await env.DB.prepare("SELECT name, carta FROM people WHERE name=?").bind(String(body.target || "")).first();
        if (!t) return err("No existe.", 404);
        return json({ name: t.name, carta: JSON.parse(t.carta || '{"f":{},"it":[]}') });
      }

      // ---------- Organizador ----------
      if (path.startsWith("/api/admin/")) {
        const key = (req.headers.get("authorization") || "").replace(/^Bearer\s+/i, "");
        if (!env.ADMIN_KEY || !safeEq(key, env.ADMIN_KEY)) return err("Clave de organizador incorrecta.", 403);
        const drawn = await isDrawn(env);

        if (path === "/api/admin/state" && req.method === "GET") {
          const [cfg, list] = await Promise.all([getCfg(env), people(env)]);
          return json({ cfg, drawn, sealed: isSealed(cfg, drawn), today: todayMadrid(), people: publicPeople(list).map((x, i) => ({ ...x, locked: list[i].lock_until > Date.now() })) });
        }

        if (path === "/api/admin/config" && req.method === "POST") {
          const cur = await getCfg(env);
          const c = body.cfg || {};
          if (isSealed(cur, drawn) && c.date !== undefined && c.date !== cur.date)
            return err("Ya ha llegado el Día D y el sorteo está sellado: la fecha no se puede cambiar.", 403);
          const cfg = {
            event: String(c.event ?? cur.event).slice(0, 60) || "Amigo Invisible",
            budget: String(c.budget ?? cur.budget).replace(/[^\d.,]/g, "").slice(0, 6),
            date: /^\d{4}-\d{2}-\d{2}$/.test(c.date || "") ? c.date : cur.date,
            missions: c.missions === undefined ? cur.missions : !!c.missions,
            excl: cur.excl
          };
          if (Array.isArray(body.people)) {
            if (drawn) return err("No se puede cambiar la lista con el sorteo hecho. Deshazlo primero.", 409);
            const names = [...new Set(body.people.map(n => String(n).trim().slice(0, 30)).filter(Boolean))];
            if (names.length > 40) return err("Máximo 40 agentes.");
            const list = await people(env), have = new Set(list.map(p => p.name));
            const stmts = [];
            names.forEach((n, i) => stmts.push(have.has(n)
              ? env.DB.prepare("UPDATE people SET pos=? WHERE name=?").bind(i, n)
              : env.DB.prepare("INSERT INTO people(name,pos) VALUES(?,?)").bind(n, i)));
            list.filter(p => !names.includes(p.name)).forEach(p => stmts.push(env.DB.prepare("DELETE FROM people WHERE name=?").bind(p.name)));
            if (stmts.length) await env.DB.batch(stmts);
            cfg.excl = (cur.excl || []).filter(([a, b]) => names.includes(a) && names.includes(b));
          }
          if (Array.isArray(body.excl)) {
            if (drawn) return err("No se pueden cambiar las parejas con el sorteo hecho.", 409);
            cfg.excl = body.excl.filter(p => Array.isArray(p) && p.length === 2 && p[0] !== p[1]).map(([a, b]) => [String(a), String(b)]).slice(0, 50);
          }
          await env.DB.prepare("INSERT INTO kv(k,v) VALUES('cfg',?) ON CONFLICT(k) DO UPDATE SET v=excluded.v").bind(JSON.stringify(cfg)).run();
          return json({ ok: true, cfg });
        }

        if (path === "/api/admin/draw" && req.method === "POST") {
          if (drawn) return err("El sorteo ya está hecho.", 409);
          const [cfg, list] = await Promise.all([getCfg(env), people(env)]);
          if (list.length < 3) return err("Hacen falta al menos 3 agentes.");
          const missing = list.filter(p => !p.pin_hash).map(p => p.name);
          if (missing.length) return err("Faltan por registrarse: " + missing.join(", "), 409);
          const pairs = derange(list.map(p => p.name), cfg.excl);
          if (!pairs) return err("Con esas parejas vetadas no sale ningún reparto. Quita alguna.");
          const ms = shuffle(MISSIONS), byName = Object.fromEntries(list.map(p => [p.name, p]));
          const stmts = [];
          for (let i = 0; i < pairs.length; i++) {
            const [g, r] = pairs[i];
            const ct = await encryptFor(byName[g].pub, { r, m: cfg.missions ? ms[i % ms.length] : null });
            stmts.push(env.DB.prepare("UPDATE people SET assignment=? WHERE name=?").bind(ct, g));
          }
          stmts.push(env.DB.prepare("INSERT INTO kv(k,v) VALUES('drawn','1') ON CONFLICT(k) DO UPDATE SET v='1'"));
          stmts.push(env.DB.prepare("INSERT INTO kv(k,v) VALUES('drawn_at',?) ON CONFLICT(k) DO UPDATE SET v=excluded.v").bind(String(Date.now())));
          await env.DB.batch(stmts);
          return json({ ok: true });
        }

        if (path === "/api/admin/undraw" && req.method === "POST") {
          if (isSealed(await getCfg(env), drawn))
            return err("Ya ha llegado el Día D: el sorteo está sellado y no se puede deshacer ni repetir.", 403);
          await env.DB.batch([
            env.DB.prepare("UPDATE people SET assignment=NULL"),
            env.DB.prepare("INSERT INTO kv(k,v) VALUES('drawn','0') ON CONFLICT(k) DO UPDATE SET v='0'")
          ]);
          return json({ ok: true });
        }

        if (path === "/api/admin/resetpin" && req.method === "POST") {
          if (drawn) return err("Con el sorteo hecho no se puede: su resultado va cifrado con su PIN. Deshaz el sorteo, resetea y vuelve a sortear.", 409);
          const r = await env.DB.prepare("UPDATE people SET pin_hash=NULL, salt=NULL, pub=NULL, wrapped=NULL, fails=0, lock_until=0 WHERE name=?")
            .bind(String(body.name || "")).run();
          return r.meta.changes ? json({ ok: true }) : err("No existe.", 404);
        }
      }
      return err("No encontrado.", 404);
    } catch (e) {
      return err("Error del servidor: " + (e && e.message || e), 500);
    }
  }
};
