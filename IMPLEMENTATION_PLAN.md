# HTTP Message Signatures Demo - Implementation Plan

A focused Node.js demo for presenting HTTP Message Signatures (RFC 9421) with three key flows:

1. **Client enrollment** - Client registers its public key with the server
2. **Good request** - Properly signed request succeeds
3. **Bad request** - Tampered request fails verification

## Tech stack & packages

### Production-ready option (recommended for presentations)

- **Runtime**: Node.js ≥ 20 (has stable Web Crypto API)
- **Framework**: **Express** (47M weekly downloads - industry standard, universally recognized)
  - Alternative: Fastify (2.9M downloads - 2-3x faster, but less known)
- **Signing/verification (RFC 9421)**:
  - `@misskey-dev/node-http-message-signatures` v1.0.0-beta.1 (niche but most actively maintained)
  - **Note**: RFC 9421 is new (published Feb 2024), so ALL libraries are relatively unknown
- **Digest fields**: Content-Digest per [RFC 9530](https://datatracker.ietf.org/doc/html/rfc9530)
- **Key formats/utilities**: [`jose`](https://www.npmjs.com/package/jose) (19M weekly downloads - widely trusted)
- **Security hardening**: `helmet`, `express-rate-limit` (mainstream Express middleware)
- **Logging**: `winston` or `pino` (both well-known)
- **Tests**: **Jest** (34.5M weekly downloads - default choice, everyone knows it)
  - Alternative: Vitest (12.5M downloads - faster, but newer)

### Why these libraries (presentation context)?

**Express over Fastify:**
- ✅ **47M weekly downloads** - Everyone recognizes it
- ✅ **Audience familiarity** - Most developers have used it
- ✅ **Easier to explain** - Simpler mental model
- ⚠️ Trade-off: 2-3x slower than Fastify, but fast enough for demo
- **For presentations**: Audience recognition > Raw performance

**Jest over Vitest:**
- ✅ **34.5M weekly downloads** - Industry default
- ✅ **Universal recognition** - "Everyone knows Jest"
- ✅ **Mature ecosystem** - More examples and resources
- ⚠️ Trade-off: Slower than Vitest, but sufficient for demo
- **For presentations**: Familiarity > Speed

**jose (good choice):**
- ✅ **19M weekly downloads** - Very popular
- ✅ **Modern & widely trusted** - panva is respected in crypto community
- ✅ **Industry standard** - Used by major projects (Next.js, Auth.js)
- Zero dependencies, works everywhere

**HTTP Message Signatures library (unavoidable niche):**
- ⚠️ **RFC 9421 is brand new** (Feb 2024) - no mainstream library exists yet
- `@misskey-dev/node-http-message-signatures` is the most actively maintained
- **For presentations**: Explain this is cutting-edge, emerging standard
- Alternative: Build your own minimal implementation to show how it works

## Project layout

```
/app
  /src
    /config
      env.ts
      security.ts               # helmet, rate-limit, body limits
    /crypto
      kid.ts                    # JWK thumbprints (RFC 7638), keyid helpers
      digest.ts                 # RFC 9530 Content-Digest helpers
      rfc9421.ts                # sign/verify wrappers
    /infra
      db.ts                     # simple in-memory store for demo
    /middleware
      verify-signature.ts       # Express middleware to verify signatures
    /routes
      admin.routes.ts           # client enrollment endpoints
      demo.routes.ts            # demo API (secrets API)
    /shared
      errors.ts                 # Problem Details JSON (RFC 7807)
      schemas.ts                # Input validation schemas
      audit.ts                  # verification audit log
    /client
      demo-client.ts            # Node.js client for demo
    server.ts
  /tests
    *.spec.ts                   # Jest test files
  /scripts
    demo.sh                     # Run full demo: enroll → good → bad
  package.json
  tsconfig.json
```

## Data model (in-memory for demo simplicity)

```typescript
// clients: Map<clientId, ClientRecord>
interface ClientRecord {
  id: string;
  name: string;
  createdAt: Date;
}

// keys: Map<kid, KeyRecord>
interface KeyRecord {
  kid: string;
  clientId: string;
  jwk: JsonWebKey;
  algorithm: string;  // e.g., "EdDSA"
  status: 'active' | 'revoked';
}

// audit: Array<AuditEntry>
interface AuditEntry {
  timestamp: Date;
  clientId: string;
  kid: string;
  result: 'ok' | 'fail';
  reason?: string;
  coveredComponents: string[];
  endpoint: string;
}

// secrets: Map<name, SecretValue>
interface SecretValue {
  name: string;
  value: string;
  allowedClientIds: string[];
}
```

## Enrollment flow (BYOK - Bring Your Own Key)

The demo uses a simple enrollment model where clients register their public key:

1. **Create client**
   ```
   POST /admin/clients
   Body: { "name": "demo-client" }
   Response: { "id": "client-123" }
   ```

2. **Upload public key**
   ```
   POST /admin/clients/:id/keys
   Body: { "kid": "key-001", "jwk": {...}, "alg": "EdDSA" }
   Response: { "kid": "key-001", "status": "active" }
   ```

3. **Use the key** in signed requests with `keyid=kid` in the signature parameters

## Request verification policy

### Covered components

The signature covers these HTTP message components (easy to explain in a presentation):

```
("@method" "@target-uri" "content-digest" "content-type" "@created" "@expires")
```

### Example headers from client

```http
Content-Digest: sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:
Signature-Input: sig1=("@method" "@target-uri" "content-digest" "content-type" "@created" "@expires");keyid="key-001";alg="ed25519";created=1730000000;expires=1730000300
Signature: sig1=:MEUCIQDxJvq...base64url...==:
```

### Server verification sequence

The Fastify `preHandler` plugin performs these checks:

1. **Parse headers**: Extract `Signature-Input` and `Signature` headers
2. **Resolve public key**: Extract `kid` from signature params → lookup JWK from in-memory store
3. **Verify Content-Digest**: Compute digest of request body and compare with `Content-Digest` header
4. **Verify signature**: Use RFC 9421 library to verify signature with the resolved JWK
5. **Enforce time window**: Check `@created` and `@expires` with clock skew tolerance (±5 min)
6. **Authorize**: Map `kid` → `clientId` → permissions for the requested resource
7. **Audit**: Log the verification result, covered components, and any failure reason

## API Endpoints

### Admin (no signature required for enrollment)

- `POST /admin/clients` - Create a new client
  - Body: `{ "name": "string" }`
  - Response: `{ "id": "string" }`

- `POST /admin/clients/:id/keys` - Register a public key for a client
  - Body: `{ "kid": "string", "jwk": {...}, "alg": "EdDSA" }`
  - Response: `{ "kid": "string", "status": "active" }`

- `GET /admin/audit` - View verification audit log
  - Response: `AuditEntry[]`

### Demo API (signature required)

- `PUT /v1/secrets/:name` - Store a secret value
  - Body: `{ "value": "string" }`
  - Auth: Client must be authorized for this secret
  - Response: `{ "name": "string", "status": "stored" }`

- `GET /v1/secrets/:name` - Retrieve a secret value
  - Auth: Client must be authorized for this secret
  - Response: `{ "name": "string", "value": "string" }`

### Utility

- `GET /` - Demo information and instructions
- `GET /health` - Health check

## Demo flows

### Flow 1: Enrollment

Client registers with the server and uploads its public key:

1. Generate Ed25519 key pair (client-side)
2. `POST /admin/clients` with name → receive `clientId`
3. `POST /admin/clients/:id/keys` with public JWK → key registered
4. Server confirms key is `active`

### Flow 2: Good request ✅

Client makes a properly signed request:

1. Prepare request body: `{ "value": "my-secret-password" }`
2. Compute `Content-Digest: sha-256=:...:`
3. Build signature base string with covered components
4. Sign with Ed25519 private key
5. Send `PUT /v1/secrets/db-password` with all signature headers
6. Server verifies → **200 OK**
7. Check audit log shows `result: "ok"`

### Flow 3: Bad request (tampered body) ❌

Demonstrate what happens when the body is modified after signing:

1. Client creates signed request (same as Flow 2)
2. **Modify the body** after signing (change `"value"` field)
3. Send request with original signature headers but modified body
4. Server computes Content-Digest → **mismatch detected**
5. Server returns **400 Bad Request** with Problem Details:
   ```json
   {
     "type": "https://httpwg.org/http-extensions/draft-ietf-httpbis-message-signatures.html#section-3.2",
     "title": "Digest Mismatch",
     "status": 400,
     "detail": "Content-Digest header does not match request body"
   }
   ```
6. Check audit log shows `result: "fail"`, `reason: "digest_mismatch"`

### Additional failure scenarios (optional)

- **Expired signature**: Send request after `@expires` timestamp → **401 Unauthorized** (`signature_expired`)
- **Unknown key**: Use unregistered `kid` → **401 Unauthorized** (`unknown_keyid`)
- **Invalid signature**: Modify signature bytes → **401 Unauthorized** (`signature_invalid`)

## Security best practices

- **Headers hardening**: `@fastify/helmet` with secure defaults
- **Rate limiting**: Per-IP limits with `@fastify/rate-limit`
- **Body limits**: 2MB max payload size; strict `Content-Type` validation
- **Schema validation**: Validate all inputs; reject unknown fields
- **No secrets in logs**: Log only digests, `kid`, and verification decisions (redact bodies)
- **Dependency hygiene**: Regular `npm audit`, keep dependencies updated
- **Key storage**: Server stores public JWKs only; never private keys
- **Clock skew tolerance**: ±5 minutes for `@created` and `@expires` validation

## Developer experience

### Verification middleware

`verify-signature.ts` - Express middleware that:
- Reads raw request body for digest computation
- Verifies signature using RFC 9421 library
- Injects `req.identity = { clientId, kid }` for downstream handlers
- Returns Problem Details JSON (RFC 7807) on failure

### Demo client

`src/client/demo-client.ts` - Node.js client that:
- Generates Ed25519 key pairs
- Signs requests per RFC 9421
- Can deliberately tamper with bodies for demo purposes
- Provides CLI interface: `npm run demo:good` and `npm run demo:bad`

### Demo script

`scripts/demo.sh` - Automated demo runner:
```bash
# Run full demo sequence
npm run demo

# Output:
# ✅ Flow 1: Client enrolled successfully
# ✅ Flow 2: Good request accepted (200 OK)
# ❌ Flow 3: Bad request rejected (400 Digest Mismatch)
```

## Testing plan

### Unit tests

- `digest.spec.ts` - RFC 9530 Content-Digest encoding/parsing (sha-256, UTF-8/binary bodies)
- `rfc9421.spec.ts` - Sign/verify happy path, wrong body, wrong key, missing components
- `kid.spec.ts` - JWK thumbprints (RFC 7638), key ID generation
- `verify-plugin.spec.ts` - Plugin integration, error handling, identity injection

### Integration tests

- **End-to-end flow**: Enroll → PUT secret → GET secret with signature verification
- **Tamper detection**: Modify body after signing → digest mismatch
- **Time windows**: Expired signatures, future signatures, clock skew tolerance
- **Unknown keys**: Request with unregistered `kid` → 401

### Security tests

- Rate limit enforcement
- Body size limits
- Log redaction (ensure request bodies aren't logged)
- Schema validation (reject unknown fields)

## Implementation checklist

### Phase 1: Core infrastructure
- [ ] Bootstrap Express with helmet, rate-limit, raw-body support
- [ ] Implement `digest.ts` - RFC 9530 Content-Digest helpers
- [ ] Implement `rfc9421.ts` - Signature generation and verification wrappers
- [ ] Implement `kid.ts` - JWK thumbprint utilities
- [ ] Set up in-memory data stores (`db.ts`)

### Phase 2: Server-side verification
- [ ] `verify-signature.ts` - Express middleware for signature verification
- [ ] Error types - Problem Details JSON (RFC 7807)
- [ ] Admin routes - Client enrollment and key registration
- [ ] Demo routes - Secrets API with signature requirement
- [ ] Audit logging

### Phase 3: Client implementation
- [ ] Demo client - Ed25519 key generation
- [ ] Demo client - Request signing
- [ ] Demo client - Tamper mode for bad requests
- [ ] CLI interface for demo flows

### Phase 4: Testing & polish
- [ ] Unit tests for crypto utilities
- [ ] Integration tests for full flows
- [ ] Demo script automation
- [ ] Documentation and presentation materials

## Presentation demo flow (3-5 minutes)

1. **Show the setup** (30 sec)
   - Explain RFC 9421 HTTP Message Signatures briefly
   - Show the covered components we'll sign

2. **Flow 1: Enrollment** (30 sec)
   - Run: `npm run demo:enroll`
   - Show client created and public key registered

3. **Flow 2: Good request** (1 min)
   - Run: `npm run demo:good`
   - Show request headers (Signature-Input, Signature, Content-Digest)
   - Server accepts → 200 OK
   - Show audit log entry: `result: "ok"`

4. **Flow 3: Bad request** (1 min)
   - Run: `npm run demo:bad`
   - Explain: "Same request, but body modified after signing"
   - Server rejects → 400 Digest Mismatch
   - Show audit log entry: `result: "fail"`, `reason: "digest_mismatch"`

5. **Q&A** (remaining time)
   - Show covered components in detail
   - Explain how this prevents tampering
   - Point to RFC 9421 and RFC 9530 on slides

## References

### RFCs

- **[RFC 9421 - HTTP Message Signatures](https://datatracker.ietf.org/doc/html/rfc9421)** - Mechanism for signing parts of HTTP messages; defines Signature-Input and Signature headers
- **[RFC 9530 - Digest Fields](https://datatracker.ietf.org/doc/html/rfc9530)** - Defines Content-Digest and Repr-Digest; obsoletes RFC 3230
- **[RFC 7807 - Problem Details](https://datatracker.ietf.org/doc/html/rfc7807)** - Standard format for HTTP API error responses
- **[RFC 7638 - JWK Thumbprint](https://datatracker.ietf.org/doc/html/rfc7638)** - JSON Web Key thumbprint calculation

### Libraries

- **[@misskey-dev/node-http-message-signatures](https://github.com/misskey-dev/node-http-message-signatures)** - RFC 9421 + RFC 9530 implementation for Node.js with Web Crypto
- **[http-message-signatures](https://github.com/dhensby/node-http-message-signatures)** - Alternative RFC 9421 implementation with good examples
- **[jose](https://www.npmjs.com/package/jose)** - JOSE/JWK/JWKS utilities for JavaScript runtimes
- **[@fastify/helmet](https://github.com/fastify/fastify-helmet)** - Security headers plugin for Fastify
- **[@fastify/rate-limit](https://github.com/fastify/fastify-rate-limit)** - Rate limiting plugin for Fastify

### Documentation

- **[MDN: Content-Digest header](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Digest)** - Overview and usage
- **[Fastify Documentation](https://www.fastify.io/)** - Modern web framework for Node.js
