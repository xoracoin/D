// Cloudflare Worker: Telegram kanallariga obunani tekshiradi.
// Sozlamalar (Worker → Settings → Variables): BOT_TOKEN (Secret), FIREBASE_URL
const H = { 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Headers': 'Content-Type', 'Access-Control-Allow-Methods': 'POST,OPTIONS' };
const J = (o, c = 200) => new Response(JSON.stringify(o), { status: c, headers: { ...H, 'Content-Type': 'application/json' } });
const enc = new TextEncoder();
async function hmac(key, data) { const k = await crypto.subtle.importKey('raw', key, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']); return new Uint8Array(await crypto.subtle.sign('HMAC', k, enc.encode(data))); }
const hex = b => [...b].map(x => x.toString(16).padStart(2, '0')).join('');
async function verify(initData, token) {
  const p = new URLSearchParams(initData || ''), hash = p.get('hash'); if (!hash) return null; p.delete('hash');
  const str = [...p.entries()].map(([k, v]) => k + '=' + v).sort().join('\n');
  const secret = await hmac(enc.encode('WebAppData'), token), sig = hex(await hmac(secret, str));
  if (sig !== hash || Date.now() / 1000 - (+p.get('auth_date') || 0) > 86400) return null;
  try { return JSON.parse(p.get('user')); } catch (e) { return null; }
}
export default {
  async fetch(req, env) {
    if (req.method === 'OPTIONS') return new Response(null, { headers: H });
    try {
      const { initData } = await req.json(), user = await verify(initData, env.BOT_TOKEN);
      if (!user) return J({ ok: false, error: 'auth' }, 401);
      const raw = (await (await fetch(env.FIREBASE_URL.replace(/\/+$/, '') + '/shared/cfg/chans.json')).json()) || '';
      const chans = String(raw).split(/[,\s]+/).map(x => x.replace('@', '')).filter(Boolean), missing = [];
      for (const c of chans) {
        const r = await (await fetch(`https://api.telegram.org/bot${env.BOT_TOKEN}/getChatMember?chat_id=@${c}&user_id=${user.id}`)).json(), st = r.ok && r.result && r.result.status;
        if (!(['creator', 'administrator', 'member'].includes(st) || (st === 'restricted' && r.result.is_member))) missing.push(c);
      }
      return J({ ok: true, subscribed: !missing.length, missing });
    } catch (e) { return J({ ok: false, error: String(e) }, 500); }
  }
};
