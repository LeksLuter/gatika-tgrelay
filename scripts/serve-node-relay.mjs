/**
 * Local development runner for the Netlify Server relay.
 *
 * Netlify itself imports netlify/server/index.mjs and starts the exported
 * http.Server; for local testing we start it on PORT (default 8787).
 */

import server from "../netlify/server/index.mjs";

const port = Number(process.env.PORT || 8787);
server.listen(port, "0.0.0.0", () => {
  console.log("Gatika Node relay listening on http://127.0.0.1:" + port);
  console.log("WebSocket path: /apiws?dst=<telegram-ip>:443&dc=2");
});
