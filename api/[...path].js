import { neon } from '@neondatabase/serverless';
import bcrypt from 'bcryptjs';
import { SignJWT, jwtVerify } from 'jose';
import { randomUUID } from 'node:crypto';

const sql = neon(process.env.DATABASE_URL);
const key = new TextEncoder().encode(process.env.JWT_SECRET || '');
const COLS = ['users', 'clientes', 'eventos', 'reports'];
const ESTADOS = ['Em espera', 'Em tratamento', 'Adjudicado', 'Não Adjudicado'];
const TIPOS = ['Eletricidade', 'Gás', 'Solar'];

const E = (s, m) => Object.assign(new Error(m), { s });
const str = (v, n = 4000) => String(v ?? '').trim().slice(0, n);
let ready;
const init = () => (ready ||= sql`CREATE TABLE IF NOT EXISTS docs (col text NOT NULL, id text NOT NULL, data jsonb NOT NULL, PRIMARY KEY (col, id))`);
const all = async col => (await sql`SELECT id, data FROM docs WHERE col = ${col}`).map(r => ({ id: r.id, ...r.data }));
const one = async (col, id) => { const r = await sql`SELECT data FROM docs WHERE col = ${col} AND id = ${id}`; return r[0] ? { id, ...r[0].data } : null; };
const put = (col, id, data) => { const { id: _i, ...d } = data; return sql`INSERT INTO docs (col, id, data) VALUES (${col}, ${id}, ${JSON.stringify(d)}::jsonb) ON CONFLICT (col, id) DO UPDATE SET data = EXCLUDED.data`; };
const del = (col, id) => sql`DELETE FROM docs WHERE col = ${col} AND id = ${id}`;
const pub = u => ({ id: u.id, nome: u.nome, user: u.user, role: u.role });

const cookie = (req, n) => ((req.headers.cookie || '').split(';').map(s => s.trim().split('=')).find(p => p[0] === n) || [])[1];
const setCookie = (res, t, age) => res.setHeader('Set-Cookie', `crm=${t}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=${age}`);
async function who(req) {
  const t = cookie(req, 'crm'); if (!t) return null;
  try { const { payload } = await jwtVerify(t, key); return await one('users', payload.sub); } catch { return null; }
}
async function login(res, u) {
  const t = await new SignJWT({}).setProtectedHeader({ alg: 'HS256' }).setSubject(u.id).setExpirationTime('7d').sign(key);
  setCookie(res, t, 7 * 24 * 3600);
}

async function clean(col, b, me, old) {
  const o = {}, admin = me.role === 'admin';
  if (col === 'clientes') {
    for (const k of ['nome', 'nif', 'tel', 'email', 'morada', 'consumo', 'notas']) if (k in b || !old) o[k] = str(b[k]);
    if ('tipos' in b || !old) o.tipos = (Array.isArray(b.tipos) ? b.tipos : []).filter(t => TIPOS.includes(t));
    if ('estado' in b) { if (!ESTADOS.includes(b.estado)) throw E(400, 'Estado inválido'); o.estado = b.estado; }
    else if (!old) o.estado = 'Em espera';
    if (admin && b.comId) { if (!(await one('users', b.comId))) throw E(400, 'Comercial inválido'); o.comId = b.comId; }
    else o.comId = old?.comId || me.id;
    if (!old && !o.nome) throw E(400, 'Nome obrigatório');
  } else if (col === 'eventos') {
    for (const k of ['titulo', 'data', 'hora', 'clienteId', 'notas']) if (k in b || !old) o[k] = str(b[k]);
    o.donoId = admin && b.donoId ? b.donoId : old?.donoId || me.id;
    if (!old && (!o.titulo || !o.data)) throw E(400, 'Título e data obrigatórios');
  }
  return { ...(old || {}), ...o };
}

export default async function handler(req, res) {
  res.setHeader('Cache-Control', 'no-store');
  try {
    await init();
    const parts = new URL(req.url, 'http://x').pathname.replace(/^\/api\/?/, '').split('/').filter(Boolean);
    const [col, id] = parts, m = req.method, b = req.body && typeof req.body === 'object' ? req.body : {};
    const users = col === 'me' || col === 'setup' ? await all('users') : null;

    if (col === 'me') { const u = await who(req); return res.json({ me: u ? pub(u) : null, setup: users.length === 0 }); }
    if (col === 'setup' && m === 'POST') {
      if (users.length) throw E(403, 'Já existe um administrador.');
      const user = str(b.user).toLowerCase(), pass = str(b.pass, 200);
      if (!user || pass.length < 6) throw E(400, 'Utilizador e palavra-passe (mín. 6 caracteres) obrigatórios.');
      const u = { id: randomUUID(), nome: str(b.nome, 100) || user, user, hash: await bcrypt.hash(pass, 10), role: 'admin' };
      await put('users', u.id, u); await login(res, u); return res.json({ me: pub(u) });
    }
    if (col === 'login' && m === 'POST') {
      const u = (await all('users')).find(x => x.user === str(b.user).toLowerCase());
      if (!u || !(await bcrypt.compare(str(b.pass, 200), u.hash))) throw E(401, 'Utilizador ou palavra-passe incorretos.');
      await login(res, u); return res.json({ me: pub(u) });
    }
    if (col === 'logout') { setCookie(res, '', 0); return res.json({ ok: true }); }

    const me = await who(req); if (!me) throw E(401, 'Sessão expirada.');
    if (!COLS.includes(col)) throw E(404, 'Não encontrado');
    const admin = me.role === 'admin';

    if (m === 'GET') {
      let l = await all(col);
      if (col === 'users') l = l.map(u => admin ? pub(u) : { id: u.id, nome: u.nome, role: u.role });
      else if (!admin) {
        if (col === 'clientes') l = l.filter(c => c.comId === me.id);
        else if (col === 'eventos') l = l.filter(e => e.donoId === me.id);
        else { const mine = new Set((await all('clientes')).filter(c => c.comId === me.id).map(c => c.id)); l = l.filter(r => r.autorId === me.id || mine.has(r.clienteId)); }
      }
      return res.json(l);
    }

    if (col === 'users') {
      if (!admin) throw E(403, 'Sem permissão.');
      if (m === 'POST') {
        const user = str(b.user).toLowerCase(), pass = str(b.pass, 200);
        if (!str(b.nome) || !user || pass.length < 6) throw E(400, 'Preencha nome, utilizador e palavra-passe (mín. 6 caracteres).');
        if ((await all('users')).some(u => u.user === user)) throw E(400, 'Esse utilizador já existe.');
        const u = { id: randomUUID(), nome: str(b.nome, 100), user, hash: await bcrypt.hash(pass, 10), role: b.role === 'admin' ? 'admin' : 'comercial' };
        await put('users', u.id, u); return res.json({ id: u.id });
      }
      const t = await one('users', id); if (!t) throw E(404, 'Não encontrado');
      if (m === 'DELETE') { if (id === me.id) throw E(400, 'Não pode apagar a própria conta.'); await del('users', id); return res.json({ ok: true }); }
      if (m === 'PATCH' || m === 'PUT') {
        if (b.pass) { if (str(b.pass, 200).length < 6) throw E(400, 'Mínimo 6 caracteres.'); t.hash = await bcrypt.hash(str(b.pass, 200), 10); }
        if (b.nome) t.nome = str(b.nome, 100);
        await put('users', id, t); return res.json({ ok: true });
      }
    }

    if (col === 'reports') {
      if (m === 'POST') {
        const c = await one('clientes', b.clienteId);
        if (!c || (!admin && c.comId !== me.id)) throw E(403, 'Sem permissão para este cliente.');
        if (!ESTADOS.includes(b.estado) || !str(b.texto)) throw E(400, 'Dados inválidos.');
        const r = { id: randomUUID(), clienteId: c.id, autorId: me.id, estado: b.estado, texto: str(b.texto, 8000), ts: Date.now() };
        await put('reports', r.id, r); return res.json({ id: r.id });
      }
      if (m === 'DELETE' && admin) { await del('reports', id); return res.json({ ok: true }); }
      throw E(403, 'Sem permissão.');
    }

    // clientes e eventos
    if (m === 'POST') { const d = await clean(col, b, me, null), nid = randomUUID(); await put(col, nid, d); return res.json({ id: nid }); }
    const old = await one(col, id); if (!old) throw E(404, 'Não encontrado');
    const owner = col === 'clientes' ? old.comId : old.donoId;
    if (!admin && owner !== me.id) throw E(403, 'Sem permissão.');
    if (m === 'DELETE') { if (col === 'clientes' && !admin) throw E(403, 'Só o admin apaga clientes.'); await del(col, id); return res.json({ ok: true }); }
    if (m === 'PUT' || m === 'PATCH') { await put(col, id, await clean(col, b, me, old)); return res.json({ ok: true }); }
    throw E(405, 'Método não suportado.');
  } catch (e) {
    res.status(e.s || 500).json({ error: e.s ? e.message : 'Erro no servidor.' });
    if (!e.s) console.error(e);
  }
}
