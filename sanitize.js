// Allowlist HTML sanitizer: rebuilds output from parsed tokens, so nothing unexpected survives.
const TAGS = { p:'p', div:'p', br:'br', strong:'strong', b:'strong', em:'em', i:'em', u:'u', s:'s', strike:'s', del:'s',
  sub:'sub', sup:'sup', h1:'h2', h2:'h2', h3:'h3', h4:'h4', blockquote:'blockquote', ul:'ul', ol:'ol', li:'li',
  a:'a', code:'code', pre:'pre', hr:'hr', img:'img' };
const VOID = new Set(['br', 'hr', 'img']);
const SKIP = /^(script|style|iframe|object|embed|noscript|textarea|svg|math|head|title)$/;

const decode = s => s.replace(/&(#x[0-9a-f]+|#\d+|amp|lt|gt|quot|apos);/gi, (_, e) => {
  e = e.toLowerCase();
  if (e[0] === '#') { try { return String.fromCodePoint(e[1] === 'x' ? parseInt(e.slice(2), 16) : +e.slice(1)); } catch { return ''; } }
  return { amp: '&', lt: '<', gt: '>', quot: '"', apos: "'" }[e];
});
const escText = s => s.replace(/&(?!(?:[a-zA-Z]+|#\d+|#x[0-9a-fA-F]+);)/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
const escAttr = s => s.replace(/&/g, '&amp;').replace(/"/g, '&quot;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
const url = (v, re) => { v = decode(v).replace(/[\u0000-\u0020\u007f-\u009f]/g, ''); return re.test(v) ? v : null; };
const LINK = /^(https?:\/\/|mailto:|#|\/(?!\/))/i;
const IMG = /^(https?:\/\/|\/uploads\/[\w-]+\.(png|jpg|gif|webp)$)/i;

function attrs(str) {
  const o = {}; const re = /([a-zA-Z-]+)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'>]+))/g; let m;
  while ((m = re.exec(str))) o[m[1].toLowerCase()] = m[2] ?? m[3] ?? m[4];
  return o;
}

function sanitize(html) {
  const out = [], stack = [];
  const re = /<!--[\s\S]*?-->|<(\/?)([a-zA-Z][a-zA-Z0-9]*)((?:"[^"]*"|'[^']*'|[^'">])*)>|([^<]+|<)/g;
  let m;
  while ((m = re.exec(html))) {
    if (m[4] !== undefined) { out.push(escText(m[4])); continue; }
    if (!m[2]) continue;
    const raw = m[2].toLowerCase(), closing = m[1] === '/';
    if (SKIP.test(raw)) {
      if (!closing) { const i = html.toLowerCase().indexOf('</' + raw, re.lastIndex); re.lastIndex = i < 0 ? html.length : i; }
      continue;
    }
    const t = TAGS[raw]; if (!t) continue;
    if (closing) {
      if (VOID.has(t)) continue;
      const i = stack.lastIndexOf(t);
      if (i >= 0) while (stack.length > i) out.push('</' + stack.pop() + '>');
      continue;
    }
    const a = attrs(m[3]);
    if (t === 'img') { const s = a.src && url(a.src, IMG); if (s) out.push('<img src="' + escAttr(s) + '" alt="' + escAttr(decode(a.alt || '')) + '">'); continue; }
    if (VOID.has(t)) { out.push('<' + t + '>'); continue; }
    if (t === 'a') { const h = a.href && url(a.href, LINK); out.push(h ? '<a href="' + escAttr(h) + '" rel="noopener noreferrer">' : '<a>'); }
    else out.push('<' + t + '>');
    stack.push(t);
  }
  while (stack.length) out.push('</' + stack.pop() + '>');
  return out.join('');
}
module.exports = sanitize;
