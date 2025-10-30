/**
 * Signature verification middleware for Express
 * Verifies HTTP Message Signatures per RFC 9421
 */

import type { Request, Response, NextFunction } from 'express';
import { webcrypto } from 'node:crypto';
import { httpbis } from 'http-message-signatures';
import { db } from '../infra/db.js';
import { verifyDigest } from '../crypto/digest.js';
import { extractKeyIdFromHeader, parseSignatureInput } from '../crypto/rfc9421.js';
import { SignatureErrors } from '../shared/errors.js';
import { logSuccess, logFailure } from '../shared/audit.js';

/**
 * Middleware to verify HTTP Message Signatures per RFC 9421
 *
 * Validates:
 * - Presence of signature headers
 * - Content-Digest verification (RFC 9530)
 * - Key existence and status
 * - Timestamp validation with clock skew tolerance
 * - Cryptographic signature verification using public key
 */
export async function verifySignatureMiddleware(
  req: Request,
  res: Response,
  next: NextFunction
): Promise<void> {
  const endpoint = req.path;
  const method = req.method;

  // Check for required headers
  const signatureInputHeader = req.headers['signature-input'];
  const signatureHeader = req.headers['signature'];
  const contentDigestHeader = req.headers['content-digest'];

  if (!signatureInputHeader || !signatureHeader) {
    res.status(401).json(SignatureErrors.missingSignature());
    return;
  }

  // Extract key ID from Signature-Input header
  const kid = extractKeyIdFromHeader(signatureInputHeader as string);

  if (!kid) {
    res.status(401).json(SignatureErrors.invalidSignature('Missing keyid parameter'));
    return;
  }

  // Look up the key
  const keyRecord = db.getKey(kid);

  if (!keyRecord) {
    logFailure('unknown', kid, 'unknown_keyid', [], endpoint, method);
    res.status(401).json(SignatureErrors.unknownKeyId(kid));
    return;
  }

  // Check if key is revoked
  if (keyRecord.status === 'revoked') {
    logFailure(keyRecord.clientId, kid, 'key_revoked', [], endpoint, method);
    res.status(401).json(SignatureErrors.revokedKey(kid));
    return;
  }

  // Parse signature input to get components for logging
  const signatureParams = parseSignatureInput(signatureInputHeader as string);

  if (!signatureParams) {
    logFailure(keyRecord.clientId, kid, 'invalid_signature_input', [], endpoint, method);
    res.status(401).json(SignatureErrors.invalidSignature('Invalid Signature-Input format'));
    return;
  }

  // Check for nonce parameter (optional but recommended for replay protection)
  if (signatureParams.nonce) {
    // Check if nonce has been used before (replay detection)
    if (db.isNonceUsed(signatureParams.nonce)) {
      logFailure(keyRecord.clientId, kid, 'replay_detected', signatureParams.components || [], endpoint, method);
      res.status(401).json({
        type: 'https://datatracker.ietf.org/doc/html/rfc9421#section-2.3',
        title: 'Replay Attack Detected',
        status: 401,
        detail: 'The nonce has already been used. This request appears to be a replay attack.',
      });
      return;
    }
  }

  // Verify Content-Digest if present
  if (contentDigestHeader && req.rawBody) {
    const digestValid = verifyDigest(req.rawBody, contentDigestHeader as string);

    if (!digestValid) {
      logFailure(
        keyRecord.clientId,
        kid,
        'digest_mismatch',
        signatureParams.components || [],
        endpoint,
        method
      );
      res.status(400).json(SignatureErrors.digestMismatch());
      return;
    }
  }

  // Perform cryptographic signature verification
  try {
    // Import the JWK public key using webcrypto
    let publicKey: webcrypto.CryptoKey;
    if (keyRecord.algorithm === 'EdDSA') {
      publicKey = await webcrypto.subtle.importKey(
        'jwk',
        keyRecord.jwk as any,
        {
          name: 'Ed25519',
          namedCurve: 'Ed25519',
        } as any,
        true,
        ['verify']
      );
    } else if (keyRecord.algorithm.startsWith('ES')) {
      // ECDSA keys
      const namedCurve = keyRecord.algorithm === 'ES256' ? 'P-256' :
                         keyRecord.algorithm === 'ES384' ? 'P-384' : 'P-521';
      publicKey = await webcrypto.subtle.importKey(
        'jwk',
        keyRecord.jwk,
        {
          name: 'ECDSA',
          namedCurve,
        },
        true,
        ['verify']
      );
    } else if (keyRecord.algorithm.startsWith('RS')) {
      // RSA keys
      publicKey = await webcrypto.subtle.importKey(
        'jwk',
        keyRecord.jwk,
        {
          name: 'RSASSA-PKCS1-v1_5',
          hash: keyRecord.algorithm === 'RS256' ? 'SHA-256' :
                keyRecord.algorithm === 'RS384' ? 'SHA-384' : 'SHA-512',
        },
        true,
        ['verify']
      );
    } else {
      throw new Error(`Unsupported algorithm: ${keyRecord.algorithm}`);
    }

    // Create a verifier function using the imported key
    const createVerifierForKey = async (data: Buffer, signature: Buffer): Promise<boolean | null> => {
      // Map algorithm names to SubtleCrypto algorithm parameters
      let algorithm: string | { name: string; hash: string };
      if (keyRecord.algorithm === 'EdDSA') {
        // Ed25519 uses 'Ed25519' algorithm name in Web Crypto API
        algorithm = 'Ed25519';
      } else if (keyRecord.algorithm === 'ES256') {
        algorithm = { name: 'ECDSA', hash: 'SHA-256' };
      } else if (keyRecord.algorithm === 'ES384') {
        algorithm = { name: 'ECDSA', hash: 'SHA-384' };
      } else if (keyRecord.algorithm === 'ES512') {
        algorithm = { name: 'ECDSA', hash: 'SHA-512' };
      } else if (keyRecord.algorithm === 'RS256') {
        algorithm = { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' };
      } else {
        throw new Error(`Unsupported algorithm: ${keyRecord.algorithm}`);
      }

      // Use crypto.subtle.verify
      return await webcrypto.subtle.verify(algorithm, publicKey, signature, data);
    };

    // Construct the message object for verification
    const message = {
      method: req.method,
      url: `${req.protocol}://${req.get('host')}${req.originalUrl}`,
      headers: {} as Record<string, string>,
    };

    // Copy headers to lowercase keys (RFC 9421 requires lowercase)
    for (const [key, value] of Object.entries(req.headers)) {
      if (value !== undefined) {
        message.headers[key.toLowerCase()] = Array.isArray(value) ? value.join(', ') : value;
      }
    }

    // Map algorithm names to library format
    const mapAlgorithmToLibraryFormat = (alg: string): string => {
      // Map JWK algorithm names to http-message-signatures library format
      const mapping: Record<string, string> = {
        'EdDSA': 'ed25519',
        'ES256': 'ecdsa-p256-sha256',
        'ES384': 'ecdsa-p384-sha384',
        'ES512': 'ecdsa-p521-sha512',
        'RS256': 'rsa-v1_5-sha256',
        'RS384': 'rsa-v1_5-sha384',
        'RS512': 'rsa-v1_5-sha512',
      };
      return mapping[alg] || alg.toLowerCase();
    };

    // Verify the signature using the library
    // Library handles timestamp validation (created/expires) with tolerance
    const CLOCK_SKEW_SECONDS = 5 * 60; // 5 minutes

    const verificationResult = await httpbis.verifyMessage(
      {
        keyLookup: async (params) => {
          // Return the key details if the keyid matches
          if (params.keyid === kid) {
            return {
              id: kid,
              algs: [mapAlgorithmToLibraryFormat(keyRecord.algorithm)],
              verify: createVerifierForKey,
            };
          }
          return null;
        },
        tolerance: CLOCK_SKEW_SECONDS, // Clock skew tolerance for timestamps
      },
      message
    );

    // verifyMessage returns true on success, false/null on failure
    if (!verificationResult) {
      logFailure(
        keyRecord.clientId,
        kid,
        'signature_verification_failed',
        signatureParams.components || [],
        endpoint,
        method
      );
      res.status(401).json(SignatureErrors.invalidSignature('Signature verification failed'));
      return;
    }

    // Store the nonce to prevent replay (if present)
    if (signatureParams.nonce) {
      // Use the expires parameter if available, otherwise use created + 5 minutes
      const expiresAt = signatureParams.expires
        ? new Date(signatureParams.expires * 1000)
        : new Date((signatureParams.created || Math.floor(Date.now() / 1000)) * 1000 + 5 * 60 * 1000);

      db.storeNonce(signatureParams.nonce, expiresAt, keyRecord.clientId, kid);
    }

    // Log successful verification
    logSuccess(
      keyRecord.clientId,
      kid,
      signatureParams.components || [],
      endpoint,
      method
    );

    // Set identity on request for downstream handlers
    req.identity = {
      clientId: keyRecord.clientId,
      kid: kid,
    };

    next();
  } catch (error: any) {
    logFailure(
      keyRecord.clientId,
      kid,
      'signature_verification_error',
      signatureParams.components || [],
      endpoint,
      method
    );
    res.status(401).json(SignatureErrors.invalidSignature(error.message || 'Verification error'));
    return;
  }
}
