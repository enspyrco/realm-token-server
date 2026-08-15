// Per-request logging for the credential mint.
//
// Until this existed, "did anyone exchange a token in the last hour?" and "is
// someone hammering /exchange?" were both unanswerable: the service logged only
// its startup line, and Caddy in front of it has no `log` directive, so it
// records errors and nothing else. Two silent layers read exactly like no
// traffic — which is how an outage and a quiet afternoon become indistinguishable.
//
// TRANSPORT FACTS ONLY, and the path is NORMALISED rather than copied. Nothing
// derived from a request body, an Authorization header, or a minted token is
// logged — and since a URL is just as capable of carrying a secret (a copied
// link, a proxy rewrite, a client bug putting a token in `/exchange/<secret>`),
// an unrecognised path is recorded as `other` rather than echoed. Excluding
// bodies and headers alone was not "by construction"; this is.
//
// Deliberately no subject: correlation would mean a Firebase uid in every line.
// Add it as a considered change if support needs it, not as a default.

const KNOWN_PATHS = new Set(['/exchange', '/livekit-token', '/healthz']);

// Origin is attacker-controlled and unbounded. Truncated so a max-size header on
// every request cannot fill the disk — which is one of the ways a log sink
// starts throwing in the first place.
const MAX_ORIGIN_LENGTH = 256;

// One JSON object per line: greppable, and it matches what LiveKit and Caddy
// already emit on this host.
//
// JSON.stringify is also the injection defence. A raw-string log format would
// let `Origin: x\n{"msg":"…"}` forge whole log entries; stringify escapes the
// newline instead.
export function makeRequestLogger({ log = console.log, now = Date.now, skipPaths = ['/healthz'] } = {}) {
  return function requestLog(req, res, next) {
    // The container healthcheck hits /healthz every 30s. Logging it would add
    // ~2900 lines a day that say nothing the healthcheck status doesn't already.
    if (skipPaths.includes(req.path)) return next();

    const startedAt = now();
    let written = false;

    // `finish` means the response was sent; `close` also fires on an aborted
    // connection, where `finish` never does. Listening only to `finish` would
    // leave a slowloris hold or a client that disconnects mid-mint completely
    // invisible — the exact silence this module exists to end, on the path that
    // matters most. Both are routed through one write, guarded so the normal
    // finish-then-close sequence logs once.
    const write = (completed) => {
      if (written) return;
      written = true;

      const rawOrigin = req.get('origin') ?? null;

      try {
        log(JSON.stringify({
          msg: 'request',
          method: req.method,
          path: KNOWN_PATHS.has(req.path) ? req.path : 'other',
          status: res.statusCode,
          durationMs: now() - startedAt,
          // false when the client vanished before the response was sent.
          completed,
          // Present/absent is itself the interesting signal: a browser sends one,
          // curl and the bot do not.
          origin: rawOrigin === null ? null : rawOrigin.slice(0, MAX_ORIGIN_LENGTH),
          // null, not false, when there was no Origin at all — a request from
          // curl or the bot is served normally, and reporting `false` there
          // would teach an operator that the bot is being denied.
          originAllowed: rawOrigin === null
            ? null
            : Boolean(res.getHeader('access-control-allow-origin')),
        }));
      } catch (err) {
        // Telemetry must never be a liveness dependency. This runs in an
        // EventEmitter listener after the response has already been sent, so an
        // escaping throw is an uncaught exception — a log sink failure would
        // take down the credential mint. Fail open, and say so once.
        try {
          console.error('requestLog: log sink threw', err?.message);
        } catch {
          // Even the fallback can fail (closed stdout). Nothing left to do that
          // would not itself be the bug this catch exists to prevent.
        }
      }
    };

    res.on('finish', () => write(true));
    res.on('close', () => write(false));

    return next();
  };
}
