# Gatika Telegram WS relay

Релей между WebSocket-клиентом Gatika и TCP-портом дата-центра Telegram.
MTProto остаётся end-to-end: релей не видит ключи и не расшифровывает трафик.

## Эндпоинт

```
wss://gatika-tgrelay.goldklonleks.workers.dev/apiws?dst=149.154.167.51:443&dc=2
```

Параметры:

- `dst` — IPv4:порт дата-центра Telegram; обязателен, проверяется по allowlist.
- `dc` — номер DC, только для диагностики.
- `probe=1` — проверить TCP-соединение до `dst`.
- `probe=2` — отправить MTProto `req_pq_multi` и вернуть `resPQ`.

## Проверка

```powershell
Invoke-WebRequest 'https://gatika-tgrelay.goldklonleks.workers.dev/?probe=1&dst=149.154.167.51:443'
Invoke-WebRequest 'https://gatika-tgrelay.goldklonleks.workers.dev/?probe=2&dst=149.154.167.51:443&dc=2'
```

Ожидаемо: `connected ...` и `resp 101B plain: ...`.

## Деплой

```powershell
cd workers/tgrelay
npx wrangler login
npx wrangler deploy
```

Нужен Cloudflare-аккаунт с Workers. Бесплатный план даёт 100 000 запросов в сутки;
WebSocket-соединение считается один раз при handshake, а не за каждый кадр.

## Ограничение LXI

Бесплатный хостинг LXI — Apache + PHP 8.3, без постоянных процессов.
Он не принимает WebSocket Upgrade и не может держать TCP-соединение до Telegram.
Поэтому этот Worker нельзя «залить в LXI» как PHP-сайт: нужен либо
постоянный Python worker на LXI Pro (€9.99/мес), либо VPS, либо Cloudflare.

## Безопасность

Релей разрешает только официальные IPv4-подсети Telegram и порты 1–65535.
Ключи MTProto через релей не передаются в открытом виде.
