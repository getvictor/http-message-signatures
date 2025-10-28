/**
 * RFC 9421 HTTP Message Signatures wrappers
 * https://datatracker.ietf.org/doc/html/rfc9421
 *
 * NOTE: This is a Phase 1 placeholder. Full implementation will come in Phase 2
 * when we add the verification middleware and client.
 */

/**
 * Components to include in the signature per demo requirements
 */
export const DEFAULT_COVERED_COMPONENTS = [
  '@method',
  '@target-uri',
  'content-digest',
  'content-type',
  '@created',
  '@expires',
] as const;

/**
 * Clock skew tolerance (5 minutes)
 */
export const CLOCK_SKEW_SECONDS = 5 * 60;

/**
 * Default signature lifetime (5 minutes)
 */
export const DEFAULT_SIGNATURE_LIFETIME_SECONDS = 5 * 60;

/**
 * Extract key ID from Signature-Input header
 *
 * @param signatureInputHeader - The Signature-Input header value
 * @returns Key ID if found, undefined otherwise
 *
 * @example
 * const kid = extractKeyIdFromHeader('sig1=(...);keyid="key-001";alg="ed25519"');
 * // Returns: "key-001"
 */
export function extractKeyIdFromHeader(
  signatureInputHeader: string
): string | undefined {
  // Format: sig1=(...);keyid="key-001";alg="ed25519";created=...;expires=...
  const match = signatureInputHeader.match(/keyid="([^"]+)"/);
  return match?.[1];
}

/**
 * Parse Signature-Input header to extract parameters
 *
 * @param signatureInputHeader - The Signature-Input header value
 * @returns Parsed parameters
 */
export function parseSignatureInput(signatureInputHeader: string): {
  components?: string[];
  keyId?: string;
  algorithm?: string;
  created?: number;
  expires?: number;
} | null {
  try {
    const keyIdMatch = signatureInputHeader.match(/keyid="([^"]+)"/);
    const algMatch = signatureInputHeader.match(/alg="([^"]+)"/);
    const createdMatch = signatureInputHeader.match(/created=(\d+)/);
    const expiresMatch = signatureInputHeader.match(/expires=(\d+)/);

    // Extract components from the parentheses
    const componentsMatch = signatureInputHeader.match(/\(([^)]+)\)/);
    const components = componentsMatch?.[1]
      .split(/\s+/)
      .map((c) => c.replace(/"/g, ''))
      .filter(Boolean);

    return {
      components,
      keyId: keyIdMatch?.[1],
      algorithm: algMatch?.[1],
      created: createdMatch ? parseInt(createdMatch[1], 10) : undefined,
      expires: expiresMatch ? parseInt(expiresMatch[1], 10) : undefined,
    };
  } catch {
    return null;
  }
}

// Placeholder types for Phase 2
export type SignMessageParams = {
  method: string;
  url: string;
  headers: Record<string, string>;
  body?: string | Buffer;
  privateKey: any;
  keyId: string;
  components?: string[];
};

export type VerifyMessageParams = {
  method: string;
  url: string;
  headers: Record<string, string>;
  body?: string | Buffer;
  publicKey: any;
};

/**
 * Sign an HTTP message per RFC 9421
 * TODO: Implement in Phase 2
 */
export async function signHttpMessage(
  params: SignMessageParams
): Promise<Record<string, string>> {
  throw new Error('signHttpMessage will be implemented in Phase 2');
}

/**
 * Verify an HTTP message signature per RFC 9421
 * TODO: Implement in Phase 2
 */
export async function verifyHttpMessage(params: VerifyMessageParams): Promise<{
  verified: boolean;
  error?: string;
  keyId?: string;
  components?: string[];
}> {
  throw new Error('verifyHttpMessage will be implemented in Phase 2');
}

/**
 * Convert JWK to CryptoKey for use in signing/verification
 * TODO: Implement in Phase 2
 */
export async function jwkToCryptoKey(
  jwk: any,
  keyType: 'private' | 'public'
): Promise<any> {
  throw new Error('jwkToCryptoKey will be implemented in Phase 2');
}
