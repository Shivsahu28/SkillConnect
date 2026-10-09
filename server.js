'use strict';
// SkillConnect backend. No npm packages needed: run with `node server.js`
const http = require('http'), fs = require('fs'), path = require('path'), crypto = require('crypto');
const PORT = process.env.PORT || 3000;
const PUB = path.join(__dirname, 'public'), DATA = path.join(__dirname, 'data');
const DBF = path.join(DATA, 'db.json'), SF = path.join(DATA, '.secret');
fs.mkdirSync(DATA, { recursive: true });
if (!fs.existsSync(SF)) fs.writeFileSync(SF, crypto.randomBytes(32).toString('hex'));
const SECRET = process.env.SECRET || fs.readFileSync(SF, 'utf8');

// ---------- passwords (scrypt) and login tokens (signed cookie) ----------
const hash = (pw, salt = crypto.randomBytes(16).toString('hex')) =>
  salt + ':' + crypto.scryptSync(pw, salt, 64).toString('hex');
const verify = (pw, stored) => {
  const [s, h] = stored.split(':'), a = Buffer.from(h, 'hex'), b = crypto.scryptSync(pw, s, 64);
  return a.length === b.length && crypto.timingSafeEqual(a, b);
};
const sign = d => crypto.createHmac('sha256', SECRET).update(d).digest('base64url');
const makeToken = id => {
  const p = Buffer.from(JSON.stringify({ id, exp: Date.now() + 7 * 864e5 })).toString('base64url');
  return p + '.' + sign(p);
};
const cookie = (v, age) => `sc=${v}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${age}`;

// ---------- database (JSON file; replace with PostgreSQL/MongoDB later) ----------
function seed() {
  const T = (id, name, skill, cat, rate, rating, langs, color) => ({ id, name, skill, cat, rate, rating, langs, color });
  return {
    users: [
      { id: 1, name: 'Riya Singh', email: 'learner@skillconnect.in', role: 'learner', password: hash('Learner@123') },
      { id: 2, name: 'Arjun Mehta', email: 'tutor@skillconnect.in', role: 'tutor', tutorId: 2, password: hash('Tutor@123') }
    ],
    tutors: [
      T(1, 'Sofia Alvarez', 'Spanish conversation', 'Languages', 600, 4.9, 'Spanish, English', '#e0527a'),
      T(2, 'Arjun Mehta', 'Python for beginners', 'Coding', 750, 4.8, 'English, Hindi', '#2f80ed'),
      T(3, 'Meera Iyer', 'Hindustani vocals', 'Music', 700, 4.9, 'Hindi, English', '#9b51e0'),
      T(4, 'Daniel Kim', 'Business English', 'Languages', 900, 4.7, 'English, Korean', '#27ae60'),
      T(5, 'Priya Sharma', 'Class 12 Physics', 'Academics', 500, 4.8, 'Hindi, English', '#f2994a'),
      T(6, 'Marco Rossi', 'Italian cooking', 'Cooking', 1000, 4.9, 'Italian, English', '#eb5757'),
      T(7, 'Ananya Das', 'UI/UX design basics', 'Art & Design', 800, 4.6, 'English, Bengali', '#00a6a6'),
      T(8, 'Rahul Verma', 'Strength and mobility', 'Fitness', 650, 4.7, 'Hindi, English', '#4f46e5')
    ],
    bookings: []
  };
}
let db = fs.existsSync(DBF) ? JSON.parse(fs.readFileSync(DBF, 'utf8')) : seed();
const save = () => { fs.writeFileSync(DBF + '.tmp', JSON.stringify(db, null, 2)); fs.renameSync(DBF + '.tmp', DBF); };
save();
const nid = arr => arr.reduce((m, x) => Math.max(m, x.id), 0) + 1;
const pub = u => ({ id: u.id, name: u.name, email: u.email, role: u.role, tutorId: u.tutorId });

// ---------- helpers ----------
function userFrom(req) {
  const m = (req.headers.cookie || '').match(/(?:^|; )sc=([^;]+)/);
  if (!m) return null;
  const [p, s] = m[1].split('.');
  if (!p || !s) return null;
  const e = sign(p);
  if (e.length !== s.length || !crypto.timingSafeEqual(Buffer.from(e), Buffer.from(s))) return null;
  try {
    const d = JSON.parse(Buffer.from(p, 'base64url'));
    return d.exp > Date.now() ? db.users.find(u => u.id === d.id) || null : null;
  } catch { return null; }
}
const send = (res, code, obj, h = {}) => {
  res.writeHead(code, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store', ...h });
  res.end(JSON.stringify(obj));
};
const body = req => new Promise((ok, no) => {
  let d = '';
  req.on('data', c => { d += c; if (d.length > 10000) { no(new Error('big')); req.destroy(); } });
  req.on('end', () => { try { ok(d ? JSON.parse(d) : {}); } catch (e) { no(e); } });
});
const tries = new Map(); // simple brute-force protection: 10 failed logins per 15 min per IP
const recent = ip => { const n = Date.now(), t = (tries.get(ip) || []).filter(x => n - x < 9e5); tries.set(ip, t); return t; };

// ---------- API ----------
async function api(req, res, p) {
  const m = req.method, me = userFrom(req), ip = req.socket.remoteAddress;
  if (p === '/api/tutors' && m === 'GET') return send(res, 200, db.tutors);

  if (p === '/api/register' && m === 'POST') {
    const { name, email, password, role } = await body(req);
    const em = String(email || '').trim().toLowerCase();
    if (!name || String(name).length > 60 || !/^\S+@\S+\.\S+$/.test(em) || String(password || '').length < 8)
      return send(res, 400, { error: 'Enter a name, a valid email and a password of 8+ characters' });
    if (db.users.some(u => u.email === em)) return send(res, 409, { error: 'Email already registered' });
    const u = { id: nid(db.users), name: String(name).trim(), email: em, role: role === 'tutor' ? 'tutor' : 'learner', password: hash(String(password)) };
    db.users.push(u); save();
    return send(res, 201, pub(u), { 'Set-Cookie': cookie(makeToken(u.id), 604800) });
  }
  if (p === '/api/login' && m === 'POST') {
    if (recent(ip).length >= 10) return send(res, 429, { error: 'Too many attempts. Try again later.' });
    const { email, password } = await body(req);
    const u = db.users.find(x => x.email === String(email || '').trim().toLowerCase());
    if (!u || !verify(String(password || ''), u.password)) {
      tries.get(ip).push(Date.now());
      return send(res, 401, { error: 'Wrong email or password' });
    }
    return send(res, 200, pub(u), { 'Set-Cookie': cookie(makeToken(u.id), 604800) });
  }
  if (p === '/api/logout' && m === 'POST') return send(res, 200, { ok: true }, { 'Set-Cookie': cookie('', 0) });

  if (!me) return send(res, 401, { error: 'Please log in' });   // everything below needs login
  if (p === '/api/me' && m === 'GET') return send(res, 200, pub(me));

  if (p === '/api/bookings' && m === 'GET')
    return send(res, 200, db.bookings.filter(b => me.role === 'learner' ? b.learnerId === me.id : b.tutorId === me.tutorId));
  if (p === '/api/bookings' && m === 'POST') {
    if (me.role !== 'learner') return send(res, 403, { error: 'Only learners can request sessions' });
    const { tutorId } = await body(req), t = db.tutors.find(x => x.id === tutorId);
    if (!t) return send(res, 404, { error: 'Tutor not found' });
    const b = { id: nid(db.bookings), learnerId: me.id, learnerName: me.name, tutorId: t.id, tutorName: t.name,
      skill: t.skill, rate: t.rate, status: 'pending', createdAt: new Date().toISOString() };
    db.bookings.push(b); save();
    return send(res, 201, b);
  }
  const mt = p.match(/^\/api\/bookings\/(\d+)$/);
  if (mt && m === 'PATCH') {
    const b = db.bookings.find(x => x.id === +mt[1]), { status } = await body(req);
    if (!b || me.role !== 'tutor' || b.tutorId !== me.tutorId) return send(res, 404, { error: 'Not found' });
    if (!['accepted', 'declined'].includes(status)) return send(res, 400, { error: 'Invalid status' });
    b.status = status; save();
    return send(res, 200, b);
  }
  send(res, 404, { error: 'Not found' });
}

// ---------- static files ----------
const types = { '.html': 'text/html; charset=utf-8', '.css': 'text/css', '.js': 'text/javascript' };
function serve(res, p) {
  const f = path.normalize(path.join(PUB, p === '/' ? 'index.html' : decodeURIComponent(p)));
  if (!f.startsWith(PUB + path.sep)) { res.writeHead(403); return res.end(); }
  fs.readFile(f, (e, d) => {
    if (e) { res.writeHead(404); return res.end('Not found'); }
    res.writeHead(200, { 'Content-Type': types[path.extname(f)] || 'application/octet-stream', 'X-Content-Type-Options': 'nosniff' });
    res.end(d);
  });
}

http.createServer(async (req, res) => {
  try {
    const p = new URL(req.url, 'http://x').pathname;
    if (p.startsWith('/api/')) await api(req, res, p); else serve(res, p);
  } catch (e) {
    if (!res.headersSent) send(res, e.message === 'big' ? 413 : 400, { error: 'Bad request' });
  }
}).listen(PORT, () => console.log(`SkillConnect running at http://localhost:${PORT}`));
