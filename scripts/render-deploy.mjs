/**
 * Создаёт (или обновляет) сервис Render для этого репозитория и ждёт деплой.
 *
 * Запускается из GitHub Actions: раннер находится вне сети, где api.render.com
 * недоступен, поэтому ключ Render передаётся только через секрет репозитория.
 *
 * Переменные окружения:
 *   RENDER_API_KEY  — ключ Render (обязателен)
 *   SERVICE_NAME    — имя сервиса (по умолчанию gatika-tgrelay)
 *   REGION          — регион Render (по умолчанию frankfurt)
 *   PLAN            — план Render (по умолчанию free)
 *   REPO_URL        — адрес репозитория (по умолчанию этот репозиторий)
 *   BRANCH          — ветка (по умолчанию master)
 */

const API = "https://api.render.com/v1";
const key = process.env.RENDER_API_KEY;
if (!key) {
  console.error("RENDER_API_KEY не задан: добавьте секрет репозитория.");
  process.exit(1);
}

const headers = {
  Authorization: "Bearer " + key,
  Accept: "application/json",
  "Content-Type": "application/json",
};

async function api(path, method = "GET", body) {
  const res = await fetch(API + path, {
    method,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const text = await res.text();
  let data = null;
  try {
    data = text ? JSON.parse(text) : null;
  } catch {
    data = text;
  }
  if (!res.ok) {
    throw new Error(method + " " + path + " -> " + res.status + ": " + text.slice(0, 1000));
  }
  return data;
}

const name = process.env.SERVICE_NAME || "gatika-tgrelay";
const region = process.env.REGION || "frankfurt";
const plan = process.env.PLAN || "free";
const repoUrl = process.env.REPO_URL || "https://github.com/LeksLuter/gatika-tgrelay";
const branch = process.env.BRANCH || "master";

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const owners = await api("/owners?limit=20");
const owner = (owners || []).map((o) => o.owner).find((o) => o && o.type === "user") ||
  (owners && owners[0] && owners[0].owner);
if (!owner) {
  throw new Error("у ключа Render нет владельца (owner)");
}
console.log("owner: " + owner.name + " (" + owner.id + ")");

const serviceDetails = {
  env: "node",
  plan,
  region,
  healthCheckPath: "/health",
  envSpecificDetails: {
    buildCommand: "npm install",
    startCommand: "node scripts/serve-node-relay.mjs",
  },
  envVars: [
    { key: "NODE_VERSION", value: "24" },
    { key: "WS_LIFETIME_MS", value: "0" },
  ],
};

const list = await api("/services?limit=100");
let service = (list || []).map((x) => x.service).find((s) => s && s.name === name);

if (service) {
  console.log("сервис уже есть: " + service.id);
  await api("/services/" + service.id, "PATCH", {
    repo: repoUrl,
    branch,
    autoDeploy: "yes",
    serviceDetails,
  });
  await api("/services/" + service.id + "/deploys", "POST", { clearCache: "do_not_clear" });
  console.log("деплой запущен");
} else {
  service = await api("/services", "POST", {
    type: "web_service",
    name,
    ownerId: owner.id,
    repo: repoUrl,
    branch,
    autoDeploy: "yes",
    serviceDetails,
  });
  console.log("сервис создан: " + service.id);
}

const id = service.id;
let url = (service.serviceDetails && service.serviceDetails.url) || "";

for (let i = 0; i < 40; i++) {
  await sleep(15000);
  let state;
  try {
    state = await api("/services/" + id);
  } catch (err) {
    console.log("[" + i + "] сервис: " + err.message);
    continue;
  }
  url = (state.serviceDetails && state.serviceDetails.url) || url;
  let deploy = null;
  try {
    const deploys = await api("/services/" + id + "/deploys?limit=1");
    deploy = deploys && deploys[0] && deploys[0].deploy;
  } catch (err) {
    console.log("[" + i + "] деплои: " + err.message);
  }
  console.log(
    "[" + i + "] status=" + (deploy ? deploy.status : "?") +
    " suspended=" + state.suspended + " url=" + url
  );
  if (deploy && deploy.status === "live") {
    console.log("RESULT_SERVICE_ID=" + id);
    console.log("RESULT_URL=" + url);
    console.log("RESULT_DASHBOARD=https://dashboard.render.com/web/" + id);
    break;
  }
  if (deploy && ["build_failed", "pre_deploy_failed", "canceled", "deactivated"].includes(deploy.status)) {
    throw new Error("деплой завершился статусом " + deploy.status);
  }
}

if (!url) {
  throw new Error("Render не вернул адрес сервиса");
}

// Проверяем сервис снаружи: health и реальный TCP до дата-центра Telegram.
for (let i = 0; i < 12; i++) {
  try {
    const health = await fetch(url + "/health", { signal: AbortSignal.timeout(20000) });
    const body = (await health.text()).slice(0, 100);
    console.log("health: " + health.status + " " + body);
    if (health.status === 200) break;
  } catch (err) {
    console.log("health: " + err.message);
  }
  await sleep(10000);
}

try {
  const probe = await fetch(url + "/apiws?dst=149.154.167.51:443&probe=1", {
    signal: AbortSignal.timeout(25000),
  });
  console.log("probe: " + probe.status + " " + (await probe.text()).slice(0, 200));
} catch (err) {
  console.log("probe: " + err.message);
}

console.log("RESULT_ENDPOINT=" + url + "/apiws?dst={dst}&dc={dc}");
