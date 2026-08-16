#!/usr/bin/env bash
# Run the real server locally against ephemeral keys.
#
#   ./scripts/dev.sh            # :8080
#   PORT=9000 ./scripts/dev.sh
#
# For poking at it by hand. `scripts/verify.sh` is the one to run before a
# commit — it boots this same server and asserts on the responses.

set -euo pipefail
cd "$(dirname "$0")/.."
# shellcheck source=scripts/devenv.sh
source scripts/devenv.sh

export PORT="${PORT:-8080}"

echo "realm-token-server dev — http://127.0.0.1:$PORT"
echo "  ephemeral ES256 keypair, project ${FIREBASE_PROJECT_ID}, trust proxy hops ${TRUST_PROXY_HOPS}"
echo
exec npm start
