/**
 * Signature verification middleware for Express
 * Verifies HTTP Message Signatures per RFC 9421
 */

import type { Request, Response, NextFunction } from 'express';
import { webcrypto } from 'node:crypto';
import { httpbis } from 'http-message-signatures';
import type { SignatureParameters } from 'http-message-signatures/lib/types';
import { db } from '../infra/db.js';
import { verifyDigest } from '../crypto/digest.js';
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

  // Verify Content-Digest if present (do this early for efficiency)
  if (contentDigestHeader && req.rawBody) {
    const digestValid = verifyDigest(req.rawBody, contentDigestHeader as string);

    if (!digestValid) {
      res.status(400).json(SignatureErrors.digestMismatch());
      return;
    }
  }

  // Track failure reason from keyLookup callback
  let failureReason: { clientId: string; kid: string; reason: string; error: any } | undefined;

  // Perform cryptographic signature verification
  try {
    // Transform Express Request to http-message-signatures's Request interface
    // Also, RFC 9421 requires lowercase header names for signature verification.
    const message = {
      method: req.method,
      url: `${req.protocol}://${req.get('host')}${req.originalUrl}`,
      headers: {} as Record<string, string>,
    };
    for (const [key, value] of Object.entries(req.headers)) {
      if (value !== undefined) {
        message.headers[key.toLowerCase()] = Array.isArray(value) ? value.join(', ') : value;
      }
    }

    // Map algorithm names to library format
    const mapAlgorithmToLibraryFormat = (alg: string): string => {
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

    // Clock skew tolerance for timestamp validation
    const CLOCK_SKEW_SECONDS = 5 * 60; // 5 minutes

    // Verify the signature using the library
    // The keyLookup callback receives parsed parameters from the library
    const verificationResult = await httpbis.verifyMessage(
      {
        keyLookup: async (params: SignatureParameters) => {
          const kid = params.keyid;

          if (!kid) {
            failureReason = { clientId: 'unknown', kid: 'unknown', reason: 'missing_keyid', error: SignatureErrors.invalidSignature('Missing keyid parameter') };
            return null;
          }

          // Look up the key
          const keyRecord = db.getKey(kid);

          if (!keyRecord) {
            logFailure('unknown', kid, 'unknown_keyid', [], endpoint, method);
            failureReason = { clientId: 'unknown', kid, reason: 'unknown_keyid', error: SignatureErrors.unknownKeyId(kid) };
            return null;
          }

          // Check if key is revoked
          if (keyRecord.status === 'revoked') {
            logFailure(keyRecord.clientId, kid, 'key_revoked', [], endpoint, method);
            failureReason = { clientId: keyRecord.clientId, kid, reason: 'key_revoked', error: SignatureErrors.revokedKey(kid) };
            return null;
          }

          // Check for nonce parameter (replay protection)
          if (params.nonce) {
            // Check if nonce has been used before (replay detection)
            if (db.isNonceUsed(params.nonce)) {
              logFailure(keyRecord.clientId, kid, 'replay_detected', [], endpoint, method);
              failureReason = {
                clientId: keyRecord.clientId,
                kid,
                reason: 'replay_detected',
                error: {
                  type: 'https://datatracker.ietf.org/doc/html/rfc9421#section-2.3',
                  title: 'Replay Attack Detected',
                  status: 401,
                  detail: 'The nonce has already been used. This request appears to be a replay attack.',
                }
              };
              return null;
            }
          }

          // Import the public key
          let publicKey: webcrypto.CryptoKey;
          if (keyRecord.algorithm === 'EdDSA') {
            publicKey = await webcrypto.subtle.importKey(
              'jwk',
              keyRecord.jwk as any,
              { name: 'Ed25519', namedCurve: 'Ed25519' } as any,
              true,
              ['verify']
            );
          } else if (keyRecord.algorithm.startsWith('ES')) {
            const namedCurve = keyRecord.algorithm === 'ES256' ? 'P-256' :
                               keyRecord.algorithm === 'ES384' ? 'P-384' : 'P-521';
            publicKey = await webcrypto.subtle.importKey(
              'jwk',
              keyRecord.jwk,
              { name: 'ECDSA', namedCurve },
              true,
              ['verify']
            );
          } else if (keyRecord.algorithm.startsWith('RS')) {
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

          // Create a verifier function
          const createVerifierForKey = async (data: Buffer, signature: Buffer): Promise<boolean | null> => {
            let algorithm: string | { name: string; hash: string };
            if (keyRecord.algorithm === 'EdDSA') {
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
            return await webcrypto.subtle.verify(algorithm, publicKey, signature, data);
          };

          // Store nonce and params for post-verification processing
          (req as any)._signatureParams = params;
          (req as any)._keyRecord = keyRecord;

          // Return the verifying key
          return {
            id: kid,
            algs: [mapAlgorithmToLibraryFormat(keyRecord.algorithm)],
            verify: createVerifierForKey,
          };
        },
        tolerance: CLOCK_SKEW_SECONDS,
      },
      message
    );

    // Check if verification failed due to specific reason
    if (failureReason) {
      res.status(401).json(failureReason.error);
      return;
    }

    // verifyMessage returns true on success, false/null on failure
    if (!verificationResult) {
      logFailure('unknown', 'unknown', 'signature_verification_failed', [], endpoint, method);
      res.status(401).json(SignatureErrors.invalidSignature('Signature verification failed'));
      return;
    }

    // Retrieve params and keyRecord stored during keyLookup
    const params = (req as any)._signatureParams as SignatureParameters;
    const keyRecord = (req as any)._keyRecord;

    // Store the nonce to prevent replay (if present)
    if (params.nonce && keyRecord) {
      // params.expires and params.created are Date objects or numbers (Unix timestamps in seconds)
      let expiresTime: number;

      if (params.expires instanceof Date) {
        expiresTime = params.expires.getTime();
      } else if (typeof params.expires === 'number') {
        expiresTime = params.expires * 1000;
      } else if (params.created instanceof Date) {
        expiresTime = params.created.getTime() + 5 * 60 * 1000;
      } else if (typeof params.created === 'number') {
        expiresTime = params.created * 1000 + 5 * 60 * 1000;
      } else {
        expiresTime = Date.now() + 5 * 60 * 1000;
      }

      const expiresAt = new Date(expiresTime);

      db.storeNonce(params.nonce, expiresAt, keyRecord.clientId, params.keyid!);
    }

    // Log successful verification
    if (keyRecord) {
      logSuccess(keyRecord.clientId, params.keyid!, [], endpoint, method);

      // Set identity on request for downstream handlers
      req.identity = {
        clientId: keyRecord.clientId,
        kid: params.keyid!,
      };
    }

    next();
  } catch (error: any) {
    res.status(401).json(SignatureErrors.invalidSignature(error.message || 'Verification error'));
    return;
  }
}
