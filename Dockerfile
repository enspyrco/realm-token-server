# Realm token server — small Node service, deployed as a Docker container on OCI
# next to LiveKit (which already holds LIVEKIT_API_SECRET in livekit.yaml).
FROM node:22-alpine

WORKDIR /app

# Install production deps first for layer caching.
COPY package.json package-lock.json* ./
RUN npm ci --omit=dev || npm install --omit=dev

COPY src ./src

ENV NODE_ENV=production
ENV PORT=8080
EXPOSE 8080

# Runtime config injected as env (never baked into the image):
#   REALM_JWT_PRIVATE_KEY   ES256 private key (PEM) — exchange handler only
#   REALM_JWT_PUBLIC_KEY    ES256 public key  (PEM) — mint handler
#   LIVEKIT_API_KEY / LIVEKIT_API_SECRET   from the box's livekit.yaml
#   FIREBASE_PROJECT_ID     e.g. adventures-in-tech-world-0 (no SA JSON needed)
CMD ["node", "src/index.js"]
