// Per-request logging for the credential mint.
//
// Until this existed, "did anyone exchange a token in the last hour?" and "is
// someone hammering /exchange?" were both unanswerable: the service logged only
// its startup line, and Caddy in front of it has no `log` directive, so it
// records errors and nothing else. Two silent layers read exactly like no
// traffic — which is how an outage and a quiet afternoon become indistinguishable.
//
// TRANSPORT FACTS ONLY. Nothing derived from a request body, an Authorization
// header, or a minted token is logged, so no credential material can reach the
// log by construction rather than by remembering to redact. That deliberately
// costs correlation (there is no subject in these lines); add it as a considered
// change if support ever needs it, rather than leaking a uid by default.

// One JSON object per line: greppable, and it matches what LiveKit and Caddy
// already emit on this host.
//
// JSON.stringify is also the injection defence. `Origin` is attacker-controlled,
// and a raw-string log format would let `Origin: x\n{"msg":"…"}` forge whole log
// entries; stringify escapes the newline instead.
export function makeRequestLogger({ log = console.log, now = Date.now, skipPaths = ['/healthz'] } = {}) {
  return function requestLog(req, res, next) {
    // The container healthcheck hits /healthz every 30s. Logging it would add
    // ~2900 lines a day that say nothing the healthcheck status doesn't already.
    if (skipPaths.includes(req.path)) return next();

    const startedAt = now();
    res.on('finish', () => {
      log(JSON.stringify({
        msg: 'request',
        method: req.method,
        path: req.path,
        status: res.statusCode,
        durationMs: now() - startedAt,
        // Present/absent is itself the interesting signal: a browser sends one,
        // curl and the bot do not.
        origin: req.get('origin') ?? null,
        // Whether CORS admitted it, read back off the response rather than
        // recomputed — so the log reports what was actually sent, not what a
        // second evaluation thinks should have been.
        originAllowed: Boolean(res.getHeader('access-control-allow-origin')),
      }));
    });

    return next();
  };
}
