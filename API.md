# Entropy Server API Reference

The Entropy Server provides a high-performance, stateless relay for decentralized messaging. It uses a combination of REST for setup and WebSockets for real-time delivery.

## 1. REST API

### `GET /pow/challenge`
Fetch a new Proof-of-Work challenge.
- **Parameters**: 
  - `type`: `registration`, `upload`, `decoy`
  - `identity_hash`: (Optional) The target identity.
- **Response**: `200 OK`
  ```json
  { "seed": "...", "difficulty": 20 }
  ```

### `POST /keys/upload`
Upload an X3DH key bundle.
- **Headers**:
  - `X-PoW-Seed`: The seed provided by the challenge.
  - `X-PoW-Nonce`: The salt/nonce you found that solves the challenge.
- **Body**: A signed JSON bundle containing identity keys and pre-keys.

### `GET /keys/fetch`
Fetch key bundles for one or more users.
- **Query**: `hashes=hash1,hash2,hash3`
- **Response**: Map of `identity_hash -> bundle`.

### `POST /account/burn`
Initiates a **Forensic Burn**.
- **Requirement**: Must be signed by the private identity key corresponding to the hash.
- **Action**: Immediately purges all keys, queued messages, and rate-limit history for that ID.

---

## 2. WebSocket Protocol (`/ws`)

### Connection Handshake
Clients connect to `/ws`. The server expects an `auth` message within the first 2 seconds.

**Authentication Message**:
```json
{
  "type": "auth",
  "payload": {
    "identity_hash": "...",
    "session_token": "..." // Re-auth
  }
}
```
OR solve a PoW challenge if no session token exists.

### Core Events
- **`send_message`**: Relay an encrypted envelope to a `TargetHash`.
- **`delivery_ack`**: Client confirms receipt, allowing the server to delete the message from the volatile queue.
- **`presence_update`**: Broadcast status to authorized peers.

---

## 3. Error Codes

| Code | Meaning | Action |
| --- | --- | --- |
| `ERR_POW_INVALID` | Nonce did not solve challenge. | Re-calculate or fetch new seed. |
| `ERR_RATE_LIMIT` | Too many requests from this IP/ID. | Wait 60 seconds. |
| `ERR_EXPIRED` | Seed has expired. | Fetch new challenge. |
| `ERR_MALFORMED` | Invalid JSON or binary header. | Check client implementation. |
