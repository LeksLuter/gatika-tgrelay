/**
 * Netlify Server entry point.
 *
 * Netlify imports this file once per instance, starts the exported
 * http.Server, and proxies HTTP + WebSocket upgrade requests to it.
 * The relay implementation stays in src/node-relay.mjs so it can be
 * tested locally without Netlify.
 */

import { createRelayServer } from "../../src/node-relay.mjs";

const server = createRelayServer();

export default server;
