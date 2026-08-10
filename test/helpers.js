import { generateKeyPairSync } from 'node:crypto';

// Generates an ephemeral ES256 (P-256) keypair in PEM form. Key material is
// created at test time and never committed — matching the Dart reference tests.
export function es256Keys() {
  const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  return {
    privateKeyPem: privateKey.export({ type: 'pkcs8', format: 'pem' }),
    publicKeyPem: publicKey.export({ type: 'spki', format: 'pem' }),
  };
}
