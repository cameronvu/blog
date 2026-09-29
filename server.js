// Zero-dependency blog server. Node 18+.
// Storage: if GITHUB_TOKEN + GITHUB_REPO are set, posts and images live in that (private) GitHub repo.
// Otherwise they are saved to local files in DATA_DIR (handy for running on your own computer).
const http = require('http'), fs = require('fs'), path = require('path'), crypto = require('crypto');
const sanitize = require('./sanitize');

const PORT = process.env.PORT || 3000;
const PASSWORD = process.env.ADMIN_PASSWORD;
if (!PASSWORD) { console.error('Set the ADMIN_PASSWORD environment variable.'); process.exit(1); }
const INDEX = fs.readFileSync(path.join(__dirname, 'public', 'index.html'));

// ---------- storage ----------
const storageError = (what, detail) => {
  console.error('Storage error (' + what + '):', detail);
  const e = new Error(what); e.http = 502; e.publicMsg = 'Storage error: could not ' + what + '. Check the server logs.'; return e;
};

function githubStore() {
  const { GITHUB_TOKEN: TOKEN, GITHUB_REPO: REPO } = process.env;
  const BRANCH = process.env.GITHUB_BRANCH || 'main', API = process.env.GITHUB_API || 'https://api.github.com';
  let sha = null;
  const call = (method, p, body, raw) => fetch(API + '/repos/' + REPO + '/contents/' + p + (method === 'GET' ? '?ref=' + encodeURIComponent(BRANCH) : ''), {
    method, body: body ? JSON.stringify(body) : undefined,
    headers: { Authorization: 'Bearer ' + TOKEN, 'User-Agent': 'my-blog', 'X-GitHub-Api-Version': '2022-11-28',
      Accept: raw ? 'application/vnd.github.raw+json' : 'application/vnd.github+json', ...(body ? { 'Content-Type': 'application/json' } : {}) },
  });
  const put = async (p, buf, message, withSha) => {
    const r = await call('PUT', p, { message, branch: BRANCH, content: buf.toString('base64'), ...(withSha && sha ? { sha } : {}) });
    if (!r.ok) throw storageError('save ' + p, r.status + ' ' + await r.text());
    return r.json();
  };
  return {
    async load() {
      const r = await call('GET', 'posts.json');
      if (r.status === 404) return [];
      if (!r.ok) throw new Error('GitHub said ' + r.status + ': ' + await r.text() + ' (check GITHUB_TOKEN, GITHUB_REPO and that the repo has a ' + BRANCH + ' branch)');
      const j = await r.json(); sha = j.sha;
      const text = j.encoding === 'base64' ? Buffer.from(j.content, 'base64').toString() : await (await call('GET', 'posts.json', null, true)).text();
      return JSON.parse(text);
    },
    async save(posts) { sha = (await put('posts.json', Buffer.from(JSON.stringify(posts, null, 2)), 'Update posts', true)).content.sha; },
    async putImage(name, buf) { await put('uploads/' + name, buf, 'Upload image', false); },
    async getImage(name) {
      const r = await call('GET', 'uploads/' + name, null, true);
      if (r.status === 404) return null;
      if (!r.ok) throw storageError('read image', r.status);
      return Buffer.from(await r.arrayBuffer());
    },
  };
}

function localStore() {
  const DIR = process.env.DATA_DIR || path.join(__dirname, 'data'), UP = path.join(DIR, 'uploads'), FILE = path.join(DIR, 'posts.json');
  fs.mkdirSync(UP, { recursive: true });
  return {
    async load() { return fs.existsSync(FILE) ? JSON.parse(fs.readFileSync(FILE, 'utf8')) : []; },
    async save(posts) { fs.writeFileSync(FILE + '.tmp', JSON.stringify(posts, null, 2)); fs.renameSync(FILE + '.tmp', FILE); },
    async putImage(name, buf) { fs.writeFileSync(path.join(UP, name), buf); },
    async getImage(name) { const f = path.join(UP, name); return fs.existsSync(f) ? fs.readFileSync(f) : null; },
  };
}

const usingGitHub = !!(process.env.GITHUB_TOKEN && process.env.GITHUB_REPO);
const store = usingGitHub ? githubStore() : localStore();
let posts = [], chain = Promise.resolve();
// Changes run one at a time so saves never collide. fn(posts) returns [newList | null, result].
const mutate = fn => {
  const run = chain.then(async () => { const [next, result] = fn(posts); if (next) { await store.save(next); posts = next; } return result; });
  chain = run.catch(() => {}); return run;
};

// ---------- auth ----------
const sha256 = s => crypto.createHash('sha256').update(s).digest();
const fails = new Map();
function checkAuth(req) {
  const ip = String(req.headers['x-forwarded-for'] || req.socket.remoteAddress).split(',')[0].trim();
  let f = fails.get(ip) || { n: 0, t: Date.now() };
  if (Date.now() - f.t > 60000) f = { n: 0, t: Date.now() };
  if (f.n >= 10) return 'locked';
  const ok = crypto.timingSafeEqual(sha256(String(req.headers['x-admin-password'] || '')), sha256(PASSWORD));
  if (!ok) { f.n++; fails.set(ip, f); }
  return ok ? 'ok' : 'bad';
}

// ---------- http ----------
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
  const cover = /^\/uploads\/[\w-]+\.(png|jpg|gif|webp)$/.test(b.cover || '') ? b.cover : '';
  const hasContent = html.replace(/<[^>]*>/g, '').trim() || /<img/.test(html);
  return title && hasContent ? { title, html, cover } : null;
}
const EXT = { 'image/png': 'png', 'image/jpeg': 'jpg', 'image/gif': 'gif', 'image/webp': 'webp' };
const MIME = { png: 'image/png', jpg: 'image/jpeg', gif: 'image/gif', webp: 'image/webp' };

const server = http.createServer(async (req, res) => {
  const p = new URL(req.url, 'http://x').pathname;
  try {
    if (req.method === 'GET' && p === '/') return send(res, 200, INDEX, 'text/html');
    if (req.method === 'GET' && p === '/api/posts') return send(res, 200, posts);

    const u = p.match(/^\/uploads\/([\w-]+\.(png|jpg|gif|webp))$/);
    if (req.method === 'GET' && u) {
      const img = await store.getImage(u[1]);
      if (!img) return send(res, 404, { error: 'Not found' });
      res.writeHead(200, { ...HEAD, 'Content-Type': MIME[u[2]], 'Cache-Control': 'public, max-age=31536000, immutable' });
      return res.end(img);
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
        await store.putImage(name, await readRaw(req, 5e6));
        return send(res, 201, { url: '/uploads/' + name });
      }
      if (req.method === 'POST' && p === '/api/posts') {
        const c = clean(await readJson(req));
        if (!c) return send(res, 400, { error: 'Title and text are required' });
        const post = { id: crypto.randomUUID(), date: new Date().toISOString(), ...c };
        await mutate(ps => [[post, ...ps], post]);
        return send(res, 201, post);
      }
      const m = p.match(/^\/api\/posts\/([\w-]+)$/);
      if (m && req.method === 'PUT') {
        const c = clean(await readJson(req));
        if (!c) return send(res, 400, { error: 'Title and text are required' });
        const out = await mutate(ps => {
          const i = ps.findIndex(x => x.id === m[1]); if (i < 0) return [null, null];
          const next = ps.slice(); next[i] = { ...ps[i], ...c }; delete next[i].body; return [next, next[i]];
        });
        return out ? send(res, 200, out) : send(res, 404, { error: 'Not found' });
      }
      if (m && req.method === 'DELETE') { await mutate(ps => [ps.filter(x => x.id !== m[1]), true]); return send(res, 200, { ok: true }); }
    }
    send(res, 404, { error: 'Not found' });
  } catch (e) { send(res, e.http || 400, { error: e.publicMsg || 'Bad request' }); }
});

store.load().then(p => {
  posts = p;
  server.listen(PORT, () => console.log('Blog running on port ' + PORT + ' (storage: ' + (usingGitHub ? 'GitHub repo ' + process.env.GITHUB_REPO : 'local files') + ')'));
}).catch(e => { console.error('Could not load posts:', e.message); process.exit(1); });