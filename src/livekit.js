import { AccessToken, RoomConfiguration, RoomAgentDispatch } from 'livekit-server-sdk';

// LiveKit access-token minting. A faithful port of enspyrco/tech_world_firebase_
// functions `retrieveLiveKitToken`: mint a room-scoped access token with agent
// dispatch embedded so the bots (clawd/gremlin/dreamfinder) auto-join whenever a
// user connects — the token-based dispatch that survives room persistence.
const AGENTS = ['clawd', 'gremlin', 'dreamfinder'];

export function makeLiveKitMinter({ apiKey, apiSecret, ttl = '1h' }) {
  if (!apiKey || !apiSecret) {
    throw new Error('makeLiveKitMinter: apiKey and apiSecret are required');
  }
  return async function mintLiveKitToken({ identity, roomName }) {
    const at = new AccessToken(apiKey, apiSecret, { identity, ttl });
    at.addGrant({
      roomJoin: true,
      room: roomName,
      canPublish: true,
      canPublishData: true,
      canSubscribe: true,
    });
    at.roomConfig = new RoomConfiguration({
      agents: AGENTS.map((agentName) => new RoomAgentDispatch({ agentName })),
    });
    return at.toJwt();
  };
}
