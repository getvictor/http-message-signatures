/**
 * RFC 7807 Problem Details for HTTP APIs
 * https://datatracker.ietf.org/doc/html/rfc7807
 */

export interface ProblemDetails {
  type: string;
  title: string;
  status: number;
  detail: string;
  instance?: string;
}

/**
 * Create a Problem Details error response
 */
export function createProblemDetails(
  status: number,
  title: string,
  detail: string,
  type?: string
): ProblemDetails {
  return {
    type: type || `https://httpwg.org/specs/rfc9110.html#status.${status}`,
    title,
    status,
    detail,
  };
}

/**
 * Common HTTP errors as Problem Details
 */
export const HttpErrors = {
  badRequest: (detail: string) =>
    createProblemDetails(400, 'Bad Request', detail),

  unauthorized: (detail: string) =>
    createProblemDetails(401, 'Unauthorized', detail),

  forbidden: (detail: string) =>
    createProblemDetails(403, 'Forbidden', detail),

  notFound: (detail: string) =>
    createProblemDetails(404, 'Not Found', detail),

  conflict: (detail: string) =>
    createProblemDetails(409, 'Conflict', detail),

  unprocessableEntity: (detail: string) =>
    createProblemDetails(422, 'Unprocessable Entity', detail),

  tooManyRequests: (detail: string) =>
    createProblemDetails(429, 'Too Many Requests', detail),

  internalServerError: (detail: string) =>
    createProblemDetails(500, 'Internal Server Error', detail),
};

/**
 * Signature verification specific errors
 */
export const SignatureErrors = {
  missingSignature: () =>
    createProblemDetails(
      401,
      'Missing Signature',
      'Request must include Signature and Signature-Input headers',
      'https://datatracker.ietf.org/doc/html/rfc9421#section-3.1'
    ),

  invalidSignature: (reason: string) =>
    createProblemDetails(
      401,
      'Invalid Signature',
      `Signature verification failed: ${reason}`,
      'https://datatracker.ietf.org/doc/html/rfc9421#section-3.2'
    ),

  unknownKeyId: (kid: string) =>
    createProblemDetails(
      401,
      'Unknown Key',
      `Key ID "${kid}" not found`,
      'https://datatracker.ietf.org/doc/html/rfc9421#section-2.3'
    ),

  digestMismatch: () =>
    createProblemDetails(
      400,
      'Digest Mismatch',
      'Content-Digest header does not match request body',
      'https://datatracker.ietf.org/doc/html/rfc9530#section-2'
    ),

  signatureExpired: () =>
    createProblemDetails(
      401,
      'Signature Expired',
      'Signature has expired based on @expires parameter',
      'https://datatracker.ietf.org/doc/html/rfc9421#section-2.3'
    ),

  revokedKey: (kid: string) =>
    createProblemDetails(
      401,
      'Revoked Key',
      `Key "${kid}" has been revoked`,
      'https://datatracker.ietf.org/doc/html/rfc9421#section-2.3'
    ),
};
