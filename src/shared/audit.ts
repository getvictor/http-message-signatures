/**
 * Audit logging utilities for signature verification
 */

import { db } from '../infra/db.js';

export interface AuditLogEntry {
  clientId: string;
  kid: string;
  result: 'ok' | 'fail';
  reason?: string;
  coveredComponents: string[];
  endpoint: string;
  method: string;
}

/**
 * Log a signature verification attempt
 */
export function logVerificationAttempt(entry: AuditLogEntry): void {
  db.addAuditEntry(entry);
}

/**
 * Log successful verification
 */
export function logSuccess(
  clientId: string,
  kid: string,
  coveredComponents: string[],
  endpoint: string,
  method: string
): void {
  logVerificationAttempt({
    clientId,
    kid,
    result: 'ok',
    coveredComponents,
    endpoint,
    method,
  });
}

/**
 * Log failed verification
 */
export function logFailure(
  clientId: string,
  kid: string,
  reason: string,
  coveredComponents: string[],
  endpoint: string,
  method: string
): void {
  logVerificationAttempt({
    clientId,
    kid,
    result: 'fail',
    reason,
    coveredComponents,
    endpoint,
    method,
  });
}
