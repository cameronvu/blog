// Zero-dependency blog server. Node 18+.
const http = require('http'), fs = require('fs'), path = require('path'), crypto = require('crypto');
const sanitize = require('./sanitize');

const PORT = process.env.PORT || 3000;
const PASSWORD = process.env.ADMIN_PASSWORD;
if (!PASSWORD) { console.error('Set the ADMIN_PASSWORD environment variable.'); process.exit(1); }

const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
const UPLOADS = path.join(DATA_DIR, 'uploads');
const FILE = path.join(DATA_DIR, 'posts.json');
fs.mkdirSync(UPLOADS, { recursive: true });
if (!fs.existsSync(FILE)) fs.writeFileSync(FILE, '[]');

const load = () => JSON.parse(fs.readFileSync(FILE, 'utf8'));
const save = posts => { const t = FILE + '.tmp'; fs.writeFileSync(t, JSON.stringify(posts, null, 2)); fs.renameSync(t, FILE); };
const INDEX = fs.readFileSync(path.join(__dirname, 'public', 'index.html'));

const sha = s => crypto.createHash('sha256').update(s).digest();
const fails = new Map();
function checkAuth(req) {
  const ip = String(req.headers['x-forwarded-for'] || req.socket.remoteAddress).split(',')[0].trim();
  let f = fails.get(ip) || { n: 0, t: Date.now() };
  if (Date.now() - f.t > 60000) f = { n: 0, t: Date.now() };
  if (f.n >= 10) return 'locked';
  const ok = crypto.timingSafeEqual(sha(String(req.headers['x-admin-password'] || '')), sha(PASSWORD));
  if (!ok) { f.n++; fails.set(ip, f); }
  return ok ? 'ok' : 'bad';
}

const HEAD = {
  'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'same-origin',
  'Content-Security-Policy': "default-src 'self'; img-src 'self' https:; style-src 'unsafe-inline'; script-src 'unsafe-inline'",
};
const send = (res, code, data, type = 'application/json') => {
  res.writeHead(code, { ...HEAD, 'Content-Type': type + '; charset=utf-8' });
  res.end(type === 'application/json' ? JSON.stringify(data) : data);
};
const readRaw = (req, max) => new Promise((resolve, reject) => {
  let n = 0; const c = [];
  req.on('data', d => { n += d.length; if (n > max) { reject(new Error('too large')); req.destroy(); } else c.push(d); });
  req.on('end', () => resolve(Buffer.concat(c)));
  req.on('error', reject);
});
const readJson = async req => JSON.parse((await readRaw(req, 1e6)).toString() || '{}');

function clean(b) {
  const title = String(b.title || '').trim().slice(0, 140);
  const html = sanitize(String(b.html || '').slice(0, 500000));
  const hasContent = html.replace(/<[^>]*>/g, '').trim() || /<img/.test(html);
  return title && hasContent ? { title, html } : null;
}
const EXT = { 'image/png': 'png', 'image/jpeg': 'jpg', 'image/gif': 'gif', 'image/webp': 'webp' };
const MIME = { png: 'image/png', jpg: 'image/jpeg', gif: 'image/gif', webp: 'image/webp' };

http.createServer(async (req, res) => {
  const p = new URL(req.url, 'http://x').pathname;
  try {
    if (req.method === 'GET' && p === '/') return send(res, 200, INDEX, 'text/html');
    if (req.method === 'GET' && p === '/api/posts') return send(res, 200, load());

    const u = p.match(/^\/uploads\/([\w-]+\.(png|jpg|gif|webp))$/);
    if (req.method === 'GET' && u) {
      const f = path.join(UPLOADS, u[1]);
      if (!fs.existsSync(f)) return send(res, 404, { error: 'Not found' });
      res.writeHead(200, { ...HEAD, 'Content-Type': MIME[u[2]], 'Cache-Control': 'public, max-age=31536000, immutable' });
      return res.end(fs.readFileSync(f));
    }

    if (p.startsWith('/api/')) {
      const a = checkAuth(req);
      if (a === 'locked') return send(res, 429, { error: 'Too many attempts. Wait a minute.' });
      if (a !== 'ok') return send(res, 401, { error: 'Wrong password' });

      if (req.method === 'POST' && p === '/api/login') return send(res, 200, { ok: true });

      if (req.method === 'POST' && p === '/api/upload') {
        const ext = EXT[String(req.headers['content-type']).split(';')[0]];
        if (!ext) return send(res, 400, { error: 'Use a PNG, JPG, GIF or WebP image' });
        const name = crypto.randomUUID() + '.' + ext;
        fs.writeFileSync(path.join(UPLOADS, name), await readRaw(req, 5e6));
        return send(res, 201, { url: '/uploads/' + name });
      }
      if (req.method === 'POST' && p === '/api/posts') {
        const c = clean(await readJson(req));
        if (!c) return send(res, 400, { error: 'Title and text are required' });
        const post = { id: crypto.randomUUID(), date: new Date().toISOString(), ...c };
        save([post, ...load()]);
        return send(res, 201, post);
      }
      const m = p.match(/^\/api\/posts\/([\w-]+)$/);
      if (m && req.method === 'PUT') {
        const c = clean(await readJson(req));
        if (!c) return send(res, 400, { error: 'Title and text are required' });
        const posts = load(), i = posts.findIndex(x => x.id === m[1]);
        if (i < 0) return send(res, 404, { error: 'Not found' });
        posts[i] = { ...posts[i], ...c }; delete posts[i].body; save(posts);
        return send(res, 200, posts[i]);
      }
      if (m && req.method === 'DELETE') { save(load().filter(x => x.id !== m[1])); return send(res, 200, { ok: true }); }
    }
    send(res, 404, { error: 'Not found' });
  } catch (e) { send(res, 400, { error: 'Bad request' }); }
}).listen(PORT, () => console.log('Blog running on port ' + PORT));
