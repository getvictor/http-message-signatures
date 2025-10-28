import {
  signHttpMessage,
  verifyHttpMessage,
  jwkToCryptoKey,
  extractKeyIdFromHeader,
  parseSignatureInput,
  DEFAULT_COVERED_COMPONENTS,
} from './rfc9421.js';
import { computeDigest } from './digest.js';
import { generateKeyPair, exportJWK } from 'jose';

describe('RFC 9421 HTTP Message Signatures', () => {
  let privateKey: CryptoKey;
  let publicKey: CryptoKey;
  const keyId = 'test-key-001';

  beforeAll(async () => {
    const keyPair = await generateKeyPair('EdDSA', { crv: 'Ed25519' });
    privateKey = keyPair.privateKey;
    publicKey = keyPair.publicKey;
  });

  describe('signHttpMessage', () => {
    it('should sign a simple GET request', async () => {
      const headers = await signHttpMessage({
        method: 'GET',
        url: 'http://localhost:3000/test',
        headers: {},
        privateKey,
        keyId,
        components: ['@method', '@target-uri'],
      });

      expect(headers['signature-input']).toBeDefined();
      expect(headers['signature']).toBeDefined();
      expect(headers['signature-input']).toContain('keyid="test-key-001"');
    });

    it('should sign a POST request with body', async () => {
      const body = JSON.stringify({ foo: 'bar' });
      const contentDigest = computeDigest(body);

      const headers = await signHttpMessage({
        method: 'POST',
        url: 'http://localhost:3000/api/data',
        headers: {
          'content-type': 'application/json',
          'content-digest': contentDigest,
        },
        body,
        privateKey,
        keyId,
      });

      expect(headers['signature-input']).toBeDefined();
      expect(headers['signature']).toBeDefined();
    });

    it('should include created and expires timestamps', async () => {
      const headers = await signHttpMessage({
        method: 'GET',
        url: 'http://localhost:3000/test',
        headers: {},
        privateKey,
        keyId,
        components: ['@method'],
      });

      expect(headers['signature-input']).toMatch(/created=\d+/);
      expect(headers['signature-input']).toMatch(/expires=\d+/);
    });

    it('should use default covered components if not specified', async () => {
      const body = JSON.stringify({ test: 'data' });
      const contentDigest = computeDigest(body);

      const headers = await signHttpMessage({
        method: 'PUT',
        url: 'http://localhost:3000/test',
        headers: {
          'content-type': 'application/json',
          'content-digest': contentDigest,
        },
        body,
        privateKey,
        keyId,
      });

      const signatureInput = headers['signature-input'];
      expect(signatureInput).toContain('@method');
      expect(signatureInput).toContain('@target-uri');
      expect(signatureInput).toContain('content-digest');
      expect(signatureInput).toContain('content-type');
    });
  });

  describe('verifyHttpMessage', () => {
    it('should verify a valid signature', async () => {
      const body = JSON.stringify({ test: 'data' });
      const contentDigest = computeDigest(body);

      const signedHeaders = await signHttpMessage({
        method: 'POST',
        url: 'http://localhost:3000/test',
        headers: {
          'content-type': 'application/json',
          'content-digest': contentDigest,
        },
        body,
        privateKey,
        keyId,
      });

      const result = await verifyHttpMessage({
        method: 'POST',
        url: 'http://localhost:3000/test',
        headers: {
          'content-type': 'application/json',
          'content-digest': contentDigest,
          ...signedHeaders,
        },
        body,
        publicKey,
      });

      expect(result.verified).toBe(true);
      expect(result.keyId).toBe(keyId);
      expect(result.error).toBeUndefined();
    });

    it('should reject tampered body', async () => {
      const originalBody = JSON.stringify({ amount: 100 });
      const contentDigest = computeDigest(originalBody);

      const signedHeaders = await signHttpMessage({
        method: 'POST',
        url: 'http://localhost:3000/transfer',
        headers: {
          'content-type': 'application/json',
          'content-digest': contentDigest,
        },
        body: originalBody,
        privateKey,
        keyId,
      });

      // Tamper with the body after signing
      const tamperedBody = JSON.stringify({ amount: 999999 });

      const result = await verifyHttpMessage({
        method: 'POST',
        url: 'http://localhost:3000/transfer',
        headers: {
          'content-type': 'application/json',
          'content-digest': contentDigest, // Original digest, not updated
          ...signedHeaders,
        },
        body: tamperedBody,
        publicKey,
      });

      expect(result.verified).toBe(false);
      expect(result.error).toBeDefined();
    });

    it('should reject request with wrong public key', async () => {
      const body = JSON.stringify({ test: 'data' });
      const contentDigest = computeDigest(body);

      const signedHeaders = await signHttpMessage({
        method: 'POST',
        url: 'http://localhost:3000/test',
        headers: {
          'content-type': 'application/json',
          'content-digest': contentDigest,
        },
        body,
        privateKey,
        keyId,
      });

      // Generate a different key pair
      const wrongKeyPair = await generateKeyPair('EdDSA', { crv: 'Ed25519' });

      const result = await verifyHttpMessage({
        method: 'POST',
        url: 'http://localhost:3000/test',
        headers: {
          'content-type': 'application/json',
          'content-digest': contentDigest,
          ...signedHeaders,
        },
        body,
        publicKey: wrongKeyPair.publicKey,
      });

      expect(result.verified).toBe(false);
    });

    it('should reject request with missing signature headers', async () => {
      const result = await verifyHttpMessage({
        method: 'GET',
        url: 'http://localhost:3000/test',
        headers: {},
        publicKey,
      });

      expect(result.verified).toBe(false);
      expect(result.error).toBeDefined();
    });
  });

  describe('jwkToCryptoKey', () => {
    it('should convert public JWK to CryptoKey', async () => {
      const jwk = await exportJWK(publicKey);
      const cryptoKey = await jwkToCryptoKey(jwk, 'public');

      expect(cryptoKey).toBeDefined();
      expect(cryptoKey.type).toBe('public');
    });

    it('should convert private JWK to CryptoKey', async () => {
      const jwk = await exportJWK(privateKey);
      const cryptoKey = await jwkToCryptoKey(jwk, 'private');

      expect(cryptoKey).toBeDefined();
      expect(cryptoKey.type).toBe('private');
    });

    it('should handle EdDSA keys', async () => {
      const keyPair = await generateKeyPair('EdDSA', { crv: 'Ed25519' });
      const publicJwk = await exportJWK(keyPair.publicKey);

      const cryptoKey = await jwkToCryptoKey(publicJwk, 'public');

      expect(cryptoKey).toBeDefined();
    });
  });

  describe('extractKeyIdFromHeader', () => {
    it('should extract key ID from Signature-Input header', () => {
      const header =
        'sig1=("@method" "@target-uri");keyid="key-001";alg="ed25519";created=1234567890';
      const keyId = extractKeyIdFromHeader(header);

      expect(keyId).toBe('key-001');
    });

    it('should return undefined if no keyid found', () => {
      const header = 'sig1=("@method" "@target-uri");alg="ed25519"';
      const keyId = extractKeyIdFromHeader(header);

      expect(keyId).toBeUndefined();
    });

    it('should handle complex key IDs', () => {
      const header =
        'sig1=(...);keyid="client-123:key-abc-def";alg="ed25519"';
      const keyId = extractKeyIdFromHeader(header);

      expect(keyId).toBe('client-123:key-abc-def');
    });
  });

  describe('parseSignatureInput', () => {
    it('should parse complete Signature-Input header', () => {
      const header =
        'sig1=("@method" "@target-uri" "content-digest");keyid="key-001";alg="ed25519";created=1234567890;expires=1234568190';
      const parsed = parseSignatureInput(header);

      expect(parsed).not.toBeNull();
      expect(parsed?.keyId).toBe('key-001');
      expect(parsed?.algorithm).toBe('ed25519');
      expect(parsed?.created).toBe(1234567890);
      expect(parsed?.expires).toBe(1234568190);
      expect(parsed?.components).toContain('@method');
      expect(parsed?.components).toContain('@target-uri');
      expect(parsed?.components).toContain('content-digest');
    });

    it('should handle header without timestamps', () => {
      const header =
        'sig1=("@method" "@target-uri");keyid="key-001";alg="ed25519"';
      const parsed = parseSignatureInput(header);

      expect(parsed).not.toBeNull();
      expect(parsed?.keyId).toBe('key-001');
      expect(parsed?.created).toBeUndefined();
      expect(parsed?.expires).toBeUndefined();
    });

    it('should parse components list', () => {
      const header =
        'sig1=("@method" "@target-uri" "content-digest" "content-type");keyid="key-001"';
      const parsed = parseSignatureInput(header);

      expect(parsed?.components).toHaveLength(4);
      expect(parsed?.components).toEqual([
        '@method',
        '@target-uri',
        'content-digest',
        'content-type',
      ]);
    });

    it('should return null for invalid header', () => {
      const parsed = parseSignatureInput('invalid header format');

      // May return an object with undefined fields or null
      expect(
        parsed === null ||
          (parsed.keyId === undefined && parsed.components === undefined)
      ).toBe(true);
    });
  });

  describe('Integration: Sign and Verify', () => {
    it('should successfully sign and verify a complete request', async () => {
      const requestBody = JSON.stringify({ value: 'secret-password' });
      const contentDigest = computeDigest(requestBody);

      // Sign the request
      const signedHeaders = await signHttpMessage({
        method: 'PUT',
        url: 'http://localhost:3000/v1/secrets/db-password',
        headers: {
          'content-type': 'application/json',
          'content-digest': contentDigest,
        },
        body: requestBody,
        privateKey,
        keyId: 'demo-key-001',
      });

      // Verify the request
      const result = await verifyHttpMessage({
        method: 'PUT',
        url: 'http://localhost:3000/v1/secrets/db-password',
        headers: {
          'content-type': 'application/json',
          'content-digest': contentDigest,
          ...signedHeaders,
        },
        body: requestBody,
        publicKey,
      });

      expect(result.verified).toBe(true);
      expect(result.keyId).toBe('demo-key-001');
    });

    it('should detect tampering in the request body', async () => {
      const originalBody = JSON.stringify({ value: 'original' });
      const contentDigest = computeDigest(originalBody);

      const signedHeaders = await signHttpMessage({
        method: 'PUT',
        url: 'http://localhost:3000/v1/secrets/test',
        headers: {
          'content-type': 'application/json',
          'content-digest': contentDigest,
        },
        body: originalBody,
        privateKey,
        keyId: 'demo-key-001',
      });

      const tamperedBody = JSON.stringify({ value: 'tampered' });

      const result = await verifyHttpMessage({
        method: 'PUT',
        url: 'http://localhost:3000/v1/secrets/test',
        headers: {
          'content-type': 'application/json',
          'content-digest': contentDigest,
          ...signedHeaders,
        },
        body: tamperedBody,
        publicKey,
      });

      expect(result.verified).toBe(false);
    });
  });
});
