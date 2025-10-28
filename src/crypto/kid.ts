/**
 * JWK Key ID (kid) utilities
 * RFC 7638 - JSON Web Key (JWK) Thumbprint
 * https://datatracker.ietf.org/doc/html/rfc7638
 *
 * Provides utilities for generating and validating key identifiers
 * using JWK thumbprints.
 */

import { calculateJwkThumbprint, type JWK } from 'jose';

/**
 * Generate a key ID (kid) from a JWK using RFC 7638 thumbprint
 *
 * @param jwk - JSON Web Key
 * @param digestAlgorithm - Hash algorithm for thumbprint (default: sha-256)
 * @returns Key ID (kid) as hex string
 *
 * @example
 * const jwk = { kty: 'EC', crv: 'P-256', x: '...', y: '...' };
 * const kid = await generateKid(jwk);
 * // Returns: "a1b2c3d4e5f6..."
 */
export async function generateKid(
  jwk: JWK,
  digestAlgorithm: 'sha256' | 'sha384' | 'sha512' = 'sha256'
): Promise<string> {
  // jose returns base64url, we'll use it as-is for kid
  const thumbprint = await calculateJwkThumbprint(jwk, digestAlgorithm);
  return thumbprint;
}

/**
 * Validate that a JWK matches the expected kid
 *
 * @param jwk - JSON Web Key
 * @param expectedKid - Expected key ID
 * @param digestAlgorithm - Hash algorithm used for thumbprint
 * @returns true if kid matches, false otherwise
 *
 * @example
 * const isValid = await validateKid(jwk, 'a1b2c3d4e5f6...');
 */
export async function validateKid(
  jwk: JWK,
  expectedKid: string,
  digestAlgorithm: 'sha256' | 'sha384' | 'sha512' = 'sha256'
): Promise<boolean> {
  const computedKid = await generateKid(jwk, digestAlgorithm);
  return computedKid === expectedKid;
}

/**
 * Generate a kid and add it to the JWK if not present
 *
 * @param jwk - JSON Web Key
 * @returns JWK with kid field set
 *
 * @example
 * const jwkWithKid = await ensureKid({ kty: 'EC', crv: 'P-256', ... });
 * // Returns: { kty: 'EC', crv: 'P-256', ..., kid: 'a1b2c3d4e5f6...' }
 */
export async function ensureKid(jwk: JWK): Promise<JWK> {
  if (jwk.kid) {
    return jwk;
  }

  const kid = await generateKid(jwk);
  return { ...jwk, kid };
}

/**
 * Validate JWK structure for use in HTTP Message Signatures
 *
 * @param jwk - JSON Web Key to validate
 * @returns Object with valid flag and error message if invalid
 */
export function validateJwkStructure(jwk: any): {
  valid: boolean;
  error?: string;
} {
  if (!jwk || typeof jwk !== 'object') {
    return { valid: false, error: 'JWK must be an object' };
  }

  if (!jwk.kty) {
    return { valid: false, error: 'JWK must have "kty" field' };
  }

  // Validate based on key type
  switch (jwk.kty) {
    case 'EC':
      if (!jwk.crv) {
        return { valid: false, error: 'EC key must have "crv" field' };
      }
      if (!jwk.x || !jwk.y) {
        return { valid: false, error: 'EC key must have "x" and "y" fields' };
      }
      break;

    case 'OKP':
      if (!jwk.crv) {
        return { valid: false, error: 'OKP key must have "crv" field' };
      }
      if (!jwk.x) {
        return { valid: false, error: 'OKP key must have "x" field' };
      }
      // Ed25519 is the primary use case
      if (jwk.crv !== 'Ed25519' && jwk.crv !== 'Ed448') {
        return {
          valid: false,
          error: 'OKP key curve must be Ed25519 or Ed448',
        };
      }
      break;

    case 'RSA':
      if (!jwk.n || !jwk.e) {
        return { valid: false, error: 'RSA key must have "n" and "e" fields' };
      }
      break;

    default:
      return { valid: false, error: `Unsupported key type: ${jwk.kty}` };
  }

  // Check for private key material
  const privateKeyFields = ['d', 'p', 'q', 'dp', 'dq', 'qi'];
  const hasPrivateKey = privateKeyFields.some((field) => jwk[field]);

  if (hasPrivateKey) {
    return {
      valid: false,
      error: 'JWK contains private key material; only public keys allowed',
    };
  }

  return { valid: true };
}
