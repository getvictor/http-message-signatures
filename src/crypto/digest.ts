/**
 * RFC 9530 Content-Digest helpers
 * https://datatracker.ietf.org/doc/html/rfc9530
 *
 * Provides utilities for computing and verifying Content-Digest headers
 * using SHA-256 algorithm with structured field encoding.
 */

import { createHash } from 'node:crypto';

export type DigestAlgorithm = 'sha-256' | 'sha-512';

/**
 * Compute SHA-256 digest of content and format per RFC 9530
 * Format: sha-256=:BASE64:
 *
 * @param content - The content to digest (string or Buffer)
 * @param algorithm - Hash algorithm (default: sha-256)
 * @returns Formatted digest string
 *
 * @example
 * const digest = computeDigest(JSON.stringify({ foo: 'bar' }));
 * // Returns: "sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:"
 */
export function computeDigest(
  content: string | Buffer,
  algorithm: DigestAlgorithm = 'sha-256'
): string {
  const hashAlgorithm = algorithm.replace('-', ''); // 'sha-256' -> 'sha256'
  const hash = createHash(hashAlgorithm);

  hash.update(content);
  const digestValue = hash.digest('base64');

  // RFC 9530 uses structured field byte sequence encoding: :base64:
  return `${algorithm}=:${digestValue}:`;
}

/**
 * Parse Content-Digest header value
 *
 * @param headerValue - Content-Digest header value
 * @returns Object with algorithm and digest value
 *
 * @example
 * const parsed = parseContentDigest("sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:");
 * // Returns: { algorithm: 'sha-256', value: 'X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=' }
 */
export function parseContentDigest(headerValue: string): {
  algorithm: string;
  value: string;
} | null {
  // Format: sha-256=:BASE64:
  const match = headerValue.match(/^([a-z0-9-]+)=:([A-Za-z0-9+/=]+):$/);

  if (!match) {
    return null;
  }

  return {
    algorithm: match[1],
    value: match[2],
  };
}

/**
 * Verify that content matches the Content-Digest header
 *
 * @param content - The content to verify
 * @param contentDigestHeader - The Content-Digest header value
 * @returns true if digest matches, false otherwise
 *
 * @example
 * const body = JSON.stringify({ foo: 'bar' });
 * const header = "sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:";
 * const isValid = verifyDigest(body, header); // true
 */
export function verifyDigest(
  content: string | Buffer,
  contentDigestHeader: string
): boolean {
  const parsed = parseContentDigest(contentDigestHeader);

  if (!parsed) {
    return false;
  }

  // Only support sha-256 and sha-512 for now
  if (parsed.algorithm !== 'sha-256' && parsed.algorithm !== 'sha-512') {
    return false;
  }

  const computed = computeDigest(content, parsed.algorithm as DigestAlgorithm);
  return computed === contentDigestHeader;
}

/**
 * Format Content-Digest header for HTTP response
 *
 * @param content - The response body content
 * @param algorithm - Hash algorithm (default: sha-256)
 * @returns Object suitable for setting as header
 *
 * @example
 * const digestHeader = formatContentDigestHeader(responseBody);
 * res.setHeader('Content-Digest', digestHeader['Content-Digest']);
 */
export function formatContentDigestHeader(
  content: string | Buffer,
  algorithm: DigestAlgorithm = 'sha-256'
): { 'Content-Digest': string } {
  return {
    'Content-Digest': computeDigest(content, algorithm),
  };
}
