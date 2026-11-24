/**
 * Релей Gatika для пятого выхода «Telegram через WebSocket».
 *
 * Зачем нужен: прямой WSS к серверам Telegram из РФ не отдаётся (302/404), а
 * мобильный TCP к DC режут. Воркер принимает WebSocket от приложения и
 * переносит байты в обычный TCP до DC — ровно то же соединение, что клиент
 * открыл бы сам, если бы сеть не мешала. MTProto остаётся зашифрованным
 * между клиентом и дата-центром: воркер видит только поток байт.
 *
 * Безопасность:
 *  - `dst` допускается только из официальных диапазонов Telegram
 *    (core.telegram.org/resources/cidr.txt). Иначе это открытый прокси.
 *  - никаких заголовков и параметров, кроме `dst` и `dc`.
 *
 * Деплой: wrangler deploy (см. wrangler.toml).
 */

import { connect } from 'cloudflare:sockets';

// Официальные диапазоны Telegram (IPv4). IPv6 воркеру не нужен: DC слушают 443.
const TELEGRAM_NETS = [
  ['91.108.4.0', 22],
  ['91.108.8.0', 22],
  ['91.108.12.0', 22],
  ['91.108.16.0', 22],
  ['91.108.20.0', 22],
  ['91.108.56.0', 22],
  ['91.105.192.0', 23],
  ['149.154.160.0', 20],
  ['185.76.151.0', 24],
];

function ipToInt(ip) {
  const parts = ip.split('.');
  if (parts.length !== 4) return null;
  let value = 0;
  for (const part of parts) {
    const n = Number(part);
    if (!Number.isInteger(n) || n < 0 || n > 255) return null;
    value = value * 256 + n;
  }
  return value;
}

function allowed(host) {
  const ip = ipToInt(host);
  if (ip === null) return false;
  return TELEGRAM_NETS.some(([base, bits]) => {
    const net = ipToInt(base);
    const size = 2 ** (32 - bits);
    return ip >= net && ip < net + size;
  });
}


// Бинарное WS-сообщение приходит как Blob: превращаем в Uint8Array.
function msgBytes(event) {
  const d = event.data;
  if (typeof d === 'string') return Promise.resolve(new TextEncoder().encode(d));
  if (d instanceof ArrayBuffer) return Promise.resolve(new Uint8Array(d));
  if (d && typeof d.arrayBuffer === 'function') return d.arrayBuffer().then((ab) => new Uint8Array(ab));
  return Promise.resolve(new Uint8Array(0));
}

export default {
  async fetch(request) {
    const url = new URL(request.url);
    const probe = Number(url.searchParams.get('probe') || 0);
    if (request.headers.get('Upgrade') !== 'websocket' && !probe) {
      return new Response('Gatika relay: только WebSocket', { status: 426 });
    }
    const dst = url.searchParams.get('dst') || '';
    const [host, portRaw] = dst.split(':');
    const port = Number(portRaw || '443');
    const dcNum = Number(url.searchParams.get('dc') || '2');
    // Порт не ограничиваем жёстко: адреса и так прибиты гвоздями к
    // официальным диапазонам Telegram (allowed ниже), а релеи звонков
    // слушают ещё и 1400/599 — для будущего UDP→TCP-конвертера в ядре.
    if (!allowed(host)) {
      return new Response('Gatika relay: адрес не из Telegram', { status: 403 });
    }

    let socket;
    try {
      socket = connect({ hostname: host, port });
    } catch (err) {
      return new Response('Gatika relay: connect failed', { status: 502 });
    }

    // Диагностика: дошли ли мы вообще до адреса. Нужна, когда WebSocket
    // открылся, а данных из Telegram нет.
    if (probe === 1) {
      try {
        await socket.opened;
        return new Response('connected ' + dst, { status: 200 });
      } catch (e) {
        return new Response('connect failed: ' + (e && e.message), { status: 502 });
      }
    }

    // Диагностика MTProto: воркер сам строит obfuscated2-init и req_pq_multi и
    // ждёт resPQ. Показывает, отвечает ли DC на MTProto с сетей Cloudflare.
    if (probe === 2) {
      const hex = await mtprotoProbe(socket, dcNum);
      return new Response(hex, { status: 200 });
    }

    const pair = new WebSocketPair();
    const [client, server] = Object.values(pair);
    server.accept();
    const writer = socket.writable.getWriter();

    // Записывать в сокет можно только после открытия: то, что отправлено
    // раньше, Cloudflare молча теряет — а первый кадр у нас как раз заголовок
    // obfuscated2, без него DC не отвечает.
    let chain = socket.opened.catch((e) => {
      throw e;
    });
    
    server.addEventListener('message', (event) => {
      chain = chain
        .then(() => msgBytes(event))
        .then((data) => writer.write(data))
        .catch(() => server.close(1011, 'write failed'));
    });

    (async () => {
      const reader = socket.readable.getReader();
      try {
        for (;;) {
          const { value, done } = await reader.read();
          if (done) break;
          if (value && value.byteLength) server.send(value);
        }
      } catch (err) {
        // Обрыв DC — закрываем WS, клиент сам переподключится.
      } finally {
        try {
          server.close(1000, 'closed');
        } catch (err) {}
        try {
          socket.close();
        } catch (err) {}
      }
    })();

    return new Response(null, { status: 101, webSocket: client });
  },
};

// Потоковое AES-CTR: ключ генерируем блоками (WebCrypto ECB через CBC).
async function ctrStream(key, iv, total) {
  const ks = new Uint8Array(total);
  const counter = Uint8Array.from(iv);
  for (let off = 0; off < total; off += 16) {
    const block = await ecbBlock(key, counter);
    const n = Math.min(16, total - off);
    ks.set(block.subarray(0, n), off);
    let carry = 1;
    for (let i = 15; i >= 0; i--) {
      carry += counter[i];
      counter[i] = carry & 255;
      carry >>= 8;
    }
  }
  return ks;
}

function xorBuf(a, b) {
  const out = new Uint8Array(a.length);
  for (let i = 0; i < a.length; i++) out[i] = a[i] ^ b[i];
  return out;
}

async function ecbBlock(key, block) {
  const k = await crypto.subtle.importKey('raw', key, 'AES-CBC', false, ['encrypt']);
  const buf = await crypto.subtle.encrypt({ name: 'AES-CBC', iv: new Uint8Array(16) }, k, block);
  return new Uint8Array(buf, 0, 16);
}

async function mtprotoProbe(socket, dcNum) {
  try {
    await socket.opened;
  } catch (e) {
    return 'connect failed: ' + (e && e.message);
  }
  const rnd = crypto.getRandomValues(new Uint8Array(64));
  if (rnd[0] === 0xef) rnd[0] = 0x42;
  if (String.fromCharCode(rnd[0],rnd[1],rnd[2],rnd[3]) === 'HEAD') rnd[0] = 0x42;
  rnd[56] = 0xef; rnd[57] = 0xef; rnd[58] = 0xef; rnd[59] = 0xef;
  rnd[60] = dcNum & 255; rnd[61] = (dcNum >> 8) & 255;
  const key = rnd.slice(8, 40);
  const iv = rnd.slice(40, 56);

  // req_pq_multi: auth_key_id=0, msg_id, msg_len=20, ctor=be7e8ef1, nonce=16
  const nonce = crypto.getRandomValues(new Uint8Array(16));
  const msg = new Uint8Array(40);
  const dv = new DataView(msg.buffer);
  dv.setUint32(16, 20, true);
  dv.setUint32(20, 0xbe7e8ef1, true);
  msg.set(nonce, 24);
  const frame = new Uint8Array(41);
  frame[0] = 10; // 40 байт = 10 слов
  frame.set(msg, 1);

  // Поток шифрования: KS[56..64] под хвост заголовка, дальше KS[64..] — данные.
  const ksFull = await ctrStream(key, iv, 64 + frame.length);
  const init = new Uint8Array(64);
  init.set(rnd.subarray(0, 56), 0);
  init.set(xorBuf(rnd.subarray(56, 64), ksFull.subarray(56, 64)), 56);
  const body = xorBuf(frame, ksFull.subarray(64));

  const writer = socket.writable.getWriter();
  await writer.write(new Uint8Array([...init, ...body]));

  const reader = socket.readable.getReader();
  try {
    const t = setTimeout(() => reader.cancel(), 8000);
    const { value, done } = await reader.read();
    clearTimeout(t);
    if (done || !value) return 'read done, 0 bytes';
    const rkey = key.slice().reverse();
    const riv = iv.slice().reverse();
    const ksR = await ctrStream(rkey, riv, value.length);
    const plain = xorBuf(value, ksR);
    const hex = Array.from(plain.subarray(0, 40)).map(b => b.toString(16).padStart(2, '0')).join('');
    const khex = Array.from(key).map(b => b.toString(16).padStart(2, '0')).join('');
    const vhex = Array.from(value).map(b => b.toString(16).padStart(2, '0')).join('');
    return 'resp ' + value.length + 'B plain: ' + hex
      + '\nkey: ' + khex
      + '\niv: ' + Array.from(iv).map(b => b.toString(16).padStart(2, '0')).join('')
      + '\ncipher: ' + vhex
  } catch (e) {
    return 'read failed: ' + (e && e.message);
  }
}

// WS-путь с таймаутом: принимает кадры клиента как есть, пишет в сокет после
// открытия, читает с таймаутом 8 с и возвращает диагностику.
async function wsProbe(request, host, port, dcNum) {
  const pair = new WebSocketPair();
  const [client, server] = Object.values(pair);
  server.accept();
  const socket = connect({ hostname: host, port });
  try {
    await socket.opened;
  } catch (e) {
    return new Response('connect failed: ' + (e && e.message), { status: 502 });
  }
  const writer = socket.writable.getWriter();
  const reader = socket.readable.getReader();
  let upBytes = 0;
  server.addEventListener('message', async (event) => {
    const data = typeof event.data === 'string' ? new TextEncoder().encode(event.data) : new Uint8Array(event.data);
    upBytes += data.length;
    try {
      await writer.write(data);
    } catch (e) {
      try { server.send('write failed: ' + (e.message)); } catch (_) {}
    }
  });
  let down = '';
  const read = reader.read().then(({ value, done }) => {
    down = done ? 'done' : Array.from(value.slice(0, 32)).map(b => b.toString(16).padStart(2, '0')).join('');
    return value;
  });
  const timer = new Promise((res) => setTimeout(() => res(null), 8000));
  const first = await Promise.race([read, timer]);
  const reply = 'ws up=' + upBytes + ' first=' + (down || 'timeout') + ' dc=' + dcNum;
  server.send(reply);
  server.close(1000, 'ok');
  try { await reader.cancel(); } catch (_) {}
  try { socket.close(); } catch (_) {}
  return new Response(null, { status: 101, webSocket: client });
}
