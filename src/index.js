import { createApp } from './server.js';
import { verifyFirebaseIdToken } from './firebase.js';
import { makeLiveKitMinter } from './livekit.js';
import { appOptionsFromEnv } from './config.js';

function requireEnv(name) {
  const v = process.env[name];
  if (!v) throw new Error(`missing required env ${name}`);
  return v;
}

// PEM env vars may arrive with literal "\n" (e.g. from a single-line secret store).
const pem = (name) => requireEnv(name).replace(/\\n/g, '\n');


const app = createApp({
  verifyProviderIdToken: verifyFirebaseIdToken,
  // The PRIVATE key reaches only the exchange handler's closure.
  privateKeyPem: pem('REALM_JWT_PRIVATE_KEY'),
  publicKeyPem: pem('REALM_JWT_PUBLIC_KEY'),
  mintLiveKitToken: makeLiveKitMinter({
    apiKey: requireEnv('LIVEKIT_API_KEY'),
    apiSecret: requireEnv('LIVEKIT_API_SECRET'),
  }),
  // Every env-derived option comes through ONE tested door (src/config.js), so a
  // dropped key fails a test rather than silently disabling a security switch.
  ...appOptionsFromEnv(process.env),
});

const port = Number(process.env.PORT || 8080);
app.listen(port, () => {
  console.log(`realm-token-server listening on :${port}`);
});
