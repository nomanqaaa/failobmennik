const cors = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET,POST,OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type',
  'Cache-Control': 'no-store'
};
const json = (data, status = 200) => new Response(JSON.stringify(data), {
  status,
  headers: { ...cors, 'Content-Type': 'application/json; charset=utf-8' }
});
const token = () => Array.from(crypto.getRandomValues(new Uint8Array(24)), b => b.toString(16).padStart(2, '0')).join('');
const MAX_FILE = 18 * 1024 * 1024;
const MAX_KV_VALUE = 25 * 1024 * 1024;

export default {
  async fetch(req, env) {
    const url = new URL(req.url);
    if (!url.pathname.startsWith('/api/')) return env.ASSETS.fetch(req);
    if (req.method === 'OPTIONS') return new Response(null, { status: 204, headers: cors });
    const parts = url.pathname.split('/').filter(Boolean);
    try {
      if (parts[1] === 'upload' && req.method === 'POST') {
        const body = await req.json();
        if (!body || typeof body.filename !== 'string' || typeof body.ciphertext !== 'string' || typeof body.salt !== 'string' || typeof body.iv !== 'string') return json({ error: 'Некорректные данные' }, 400);
        if (!Number.isInteger(body.size) || body.size < 0 || body.size > MAX_FILE) return json({ error: 'Максимальный размер файла в бесплатной версии — 18 МБ' }, 413);
        const ttl = [3600, 86400, 604800].includes(body.ttl) ? body.ttl : 86400;
        const id = token(), expiresAt = Date.now() + ttl * 1000;
        const record = {
          token: id,
          filename: body.filename.slice(0, 255),
          mime: String(body.mime || 'application/octet-stream').slice(0, 150),
          size: body.size,
          salt: body.salt,
          iv: body.iv,
          ciphertext: body.ciphertext,
          expiresAt,
          createdAt: Date.now()
        };
        const serialized = JSON.stringify(record);
        // KV has a 25 MiB value limit. 18 MiB files fit even after base64 expansion and JSON metadata.
        if (new TextEncoder().encode(serialized).byteLength > MAX_KV_VALUE) return json({ error: 'Зашифрованный файл превышает лимит хранилища; выберите файл меньше 18 МБ' }, 413);
        await env.FILES.put(id, serialized, { expirationTtl: ttl });
        return json({ token: id, expiresAt }, 201);
      }
      if (parts[1] === 'file' && parts[2] && req.method === 'GET') {
        const id = parts[2];
        if (!/^[a-f0-9]{48}$/.test(id)) return json({ error: 'Ссылка недействительна' }, 404);
        const raw = await env.FILES.get(id);
        if (!raw) return json({ error: 'Ссылка не найдена, истекла или уже использована' }, 404);
        const d = JSON.parse(raw);
        if (Date.now() > d.expiresAt) {
          await env.FILES.delete(id);
          return json({ error: 'Срок действия ссылки истёк' }, 410);
        }
        return json(d);
      }
      if (parts[1] === 'consume' && parts[2] && req.method === 'POST') {
        const id = parts[2];
        if (!/^[a-f0-9]{48}$/.test(id)) return json({ error: 'Ссылка недействительна' }, 404);
        const exists = await env.FILES.get(id);
        if (!exists) return json({ error: 'Ссылка уже использована или истекла' }, 404);
        await env.FILES.delete(id);
        return json({ ok: true });
      }
      return json({ error: 'Маршрут не найден' }, 404);
    } catch (e) {
      return json({ error: 'Ошибка сервера. Проверьте лимиты и настройки KV.' }, 500);
    }
  }
};
