import {
  generateKid,
  validateKid,
  ensureKid,
  validateJwkStructure,
} from './kid.js';
import { generateKeyPair, exportJWK } from 'jose';

describe('JWK Key ID utilities', () => {
  describe('generateKid', () => {
    it('should generate kid from Ed25519 JWK', async () => {
      const { publicKey } = await generateKeyPair('EdDSA', { crv: 'Ed25519' });
      const jwk = await exportJWK(publicKey);

      const kid = await generateKid(jwk);

      expect(kid).toBeDefined();
      expect(typeof kid).toBe('string');
      expect(kid.length).toBeGreaterThan(0);
    });

    it('should generate consistent kid for same JWK', async () => {
      const { publicKey } = await generateKeyPair('EdDSA', { crv: 'Ed25519' });
      const jwk = await exportJWK(publicKey);

      const kid1 = await generateKid(jwk);
      const kid2 = await generateKid(jwk);

      expect(kid1).toBe(kid2);
    });

    it('should generate different kids for different keys', async () => {
      const { publicKey: pk1 } = await generateKeyPair('EdDSA', {
        crv: 'Ed25519',
      });
      const { publicKey: pk2 } = await generateKeyPair('EdDSA', {
        crv: 'Ed25519',
      });

      const jwk1 = await exportJWK(pk1);
      const jwk2 = await exportJWK(pk2);

      const kid1 = await generateKid(jwk1);
      const kid2 = await generateKid(jwk2);

      expect(kid1).not.toBe(kid2);
    });

    it('should support different digest algorithms', async () => {
      const { publicKey } = await generateKeyPair('EdDSA', { crv: 'Ed25519' });
      const jwk = await exportJWK(publicKey);

      const kid256 = await generateKid(jwk, 'sha256');
      const kid384 = await generateKid(jwk, 'sha384');
      const kid512 = await generateKid(jwk, 'sha512');

      expect(kid256).not.toBe(kid384);
      expect(kid384).not.toBe(kid512);
      expect(kid256).not.toBe(kid512);
    });
  });

  describe('validateKid', () => {
    it('should validate correct kid', async () => {
      const { publicKey } = await generateKeyPair('EdDSA', { crv: 'Ed25519' });
      const jwk = await exportJWK(publicKey);
      const kid = await generateKid(jwk);

      const isValid = await validateKid(jwk, kid);

      expect(isValid).toBe(true);
    });

    it('should reject incorrect kid', async () => {
      const { publicKey } = await generateKeyPair('EdDSA', { crv: 'Ed25519' });
      const jwk = await exportJWK(publicKey);

      const isValid = await validateKid(jwk, 'wrong-kid-value');

      expect(isValid).toBe(false);
    });

    it('should validate with correct digest algorithm', async () => {
      const { publicKey } = await generateKeyPair('EdDSA', { crv: 'Ed25519' });
      const jwk = await exportJWK(publicKey);
      const kid = await generateKid(jwk, 'sha512');

      const isValid = await validateKid(jwk, kid, 'sha512');

      expect(isValid).toBe(true);
    });
  });

  describe('ensureKid', () => {
    it('should add kid to JWK without kid', async () => {
      const { publicKey } = await generateKeyPair('EdDSA', { crv: 'Ed25519' });
      const jwk = await exportJWK(publicKey);

      // Remove kid if it exists
      delete jwk.kid;

      const jwkWithKid = await ensureKid(jwk);

      expect(jwkWithKid.kid).toBeDefined();
      expect(typeof jwkWithKid.kid).toBe('string');
    });

    it('should preserve existing kid', async () => {
      const { publicKey } = await generateKeyPair('EdDSA', { crv: 'Ed25519' });
      const jwk = await exportJWK(publicKey);
      const existingKid = 'my-custom-kid';

      jwk.kid = existingKid;

      const jwkWithKid = await ensureKid(jwk);

      expect(jwkWithKid.kid).toBe(existingKid);
    });

    it('should not mutate original JWK', async () => {
      const { publicKey } = await generateKeyPair('EdDSA', { crv: 'Ed25519' });
      const jwk = await exportJWK(publicKey);

      delete jwk.kid;
      const original = { ...jwk };

      await ensureKid(jwk);

      expect(jwk).toEqual(original);
    });
  });

  describe('validateJwkStructure', () => {
    it('should validate valid Ed25519 public key', async () => {
      const { publicKey } = await generateKeyPair('EdDSA', { crv: 'Ed25519' });
      const jwk = await exportJWK(publicKey);

      const result = validateJwkStructure(jwk);

      expect(result.valid).toBe(true);
      expect(result.error).toBeUndefined();
    });

    it('should validate valid EC public key', async () => {
      const { publicKey } = await generateKeyPair('ES256');
      const jwk = await exportJWK(publicKey);

      const result = validateJwkStructure(jwk);

      expect(result.valid).toBe(true);
    });

    it('should reject null or undefined', () => {
      expect(validateJwkStructure(null).valid).toBe(false);
      expect(validateJwkStructure(undefined).valid).toBe(false);
    });

    it('should reject non-object', () => {
      expect(validateJwkStructure('not an object').valid).toBe(false);
      expect(validateJwkStructure(123).valid).toBe(false);
    });

    it('should reject JWK without kty', () => {
      const result = validateJwkStructure({ x: 'value' });

      expect(result.valid).toBe(false);
      expect(result.error).toContain('kty');
    });

    it('should reject EC key without crv', () => {
      const result = validateJwkStructure({ kty: 'EC', x: 'val', y: 'val' });

      expect(result.valid).toBe(false);
      expect(result.error).toContain('crv');
    });

    it('should reject EC key without x or y', () => {
      const result1 = validateJwkStructure({ kty: 'EC', crv: 'P-256', y: 'val' });
      const result2 = validateJwkStructure({ kty: 'EC', crv: 'P-256', x: 'val' });

      expect(result1.valid).toBe(false);
      expect(result2.valid).toBe(false);
    });

    it('should reject OKP key without crv', () => {
      const result = validateJwkStructure({ kty: 'OKP', x: 'val' });

      expect(result.valid).toBe(false);
      expect(result.error).toContain('crv');
    });

    it('should reject OKP key without x', () => {
      const result = validateJwkStructure({ kty: 'OKP', crv: 'Ed25519' });

      expect(result.valid).toBe(false);
      expect(result.error).toContain('x');
    });

    it('should reject OKP key with unsupported curve', () => {
      const result = validateJwkStructure({
        kty: 'OKP',
        crv: 'X25519',
        x: 'val',
      });

      expect(result.valid).toBe(false);
      expect(result.error).toContain('Ed25519');
    });

    it('should reject RSA key without n or e', () => {
      const result1 = validateJwkStructure({ kty: 'RSA', e: 'AQAB' });
      const result2 = validateJwkStructure({ kty: 'RSA', n: 'val' });

      expect(result1.valid).toBe(false);
      expect(result2.valid).toBe(false);
    });

    it('should reject private key material', async () => {
      const { privateKey } = await generateKeyPair('EdDSA', {
        crv: 'Ed25519',
      });
      const privateJwk = await exportJWK(privateKey);

      const result = validateJwkStructure(privateJwk);

      expect(result.valid).toBe(false);
      expect(result.error).toContain('private key');
    });

    it('should reject unsupported key type', () => {
      const result = validateJwkStructure({ kty: 'oct', k: 'secret' });

      expect(result.valid).toBe(false);
      expect(result.error).toContain('Unsupported');
    });
  });
});
