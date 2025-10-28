/**
 * Input validation schemas
 */

import { validateJwkStructure } from '../crypto/kid.js';
import type { JWK } from 'jose';

/**
 * Validate client creation request
 */
export function validateClientRequest(body: any): {
  valid: boolean;
  error?: string;
  data?: { name: string };
} {
  if (!body || typeof body !== 'object') {
    return { valid: false, error: 'Request body must be an object' };
  }

  if (!body.name || typeof body.name !== 'string') {
    return { valid: false, error: 'Field "name" is required and must be a string' };
  }

  if (body.name.trim().length === 0) {
    return { valid: false, error: 'Field "name" cannot be empty' };
  }

  if (body.name.length > 100) {
    return { valid: false, error: 'Field "name" must be 100 characters or less' };
  }

  return { valid: true, data: { name: body.name.trim() } };
}

/**
 * Validate key registration request
 */
export function validateKeyRequest(body: any): {
  valid: boolean;
  error?: string;
  data?: { kid: string; jwk: JWK; algorithm: string };
} {
  if (!body || typeof body !== 'object') {
    return { valid: false, error: 'Request body must be an object' };
  }

  // Validate kid
  if (!body.kid || typeof body.kid !== 'string') {
    return { valid: false, error: 'Field "kid" is required and must be a string' };
  }

  if (body.kid.trim().length === 0) {
    return { valid: false, error: 'Field "kid" cannot be empty' };
  }

  // Validate algorithm
  if (!body.alg || typeof body.alg !== 'string') {
    return { valid: false, error: 'Field "alg" is required and must be a string' };
  }

  const validAlgorithms = ['EdDSA', 'ES256', 'ES384', 'ES512', 'RS256', 'RS384', 'RS512'];
  if (!validAlgorithms.includes(body.alg)) {
    return {
      valid: false,
      error: `Field "alg" must be one of: ${validAlgorithms.join(', ')}`,
    };
  }

  // Validate JWK
  if (!body.jwk || typeof body.jwk !== 'object') {
    return { valid: false, error: 'Field "jwk" is required and must be an object' };
  }

  const jwkValidation = validateJwkStructure(body.jwk);
  if (!jwkValidation.valid) {
    return { valid: false, error: `Invalid JWK: ${jwkValidation.error}` };
  }

  return {
    valid: true,
    data: {
      kid: body.kid.trim(),
      jwk: body.jwk,
      algorithm: body.alg,
    },
  };
}

/**
 * Validate secret value request
 */
export function validateSecretRequest(body: any): {
  valid: boolean;
  error?: string;
  data?: { value: string };
} {
  if (!body || typeof body !== 'object') {
    return { valid: false, error: 'Request body must be an object' };
  }

  if (!body.value || typeof body.value !== 'string') {
    return { valid: false, error: 'Field "value" is required and must be a string' };
  }

  if (body.value.length === 0) {
    return { valid: false, error: 'Field "value" cannot be empty' };
  }

  if (body.value.length > 10000) {
    return { valid: false, error: 'Field "value" must be 10000 characters or less' };
  }

  return { valid: true, data: { value: body.value } };
}

/**
 * Validate secret name parameter
 */
export function validateSecretName(name: string): {
  valid: boolean;
  error?: string;
} {
  if (!name || typeof name !== 'string') {
    return { valid: false, error: 'Secret name is required' };
  }

  if (name.trim().length === 0) {
    return { valid: false, error: 'Secret name cannot be empty' };
  }

  // Only allow alphanumeric, hyphens, and underscores
  if (!/^[a-zA-Z0-9_-]+$/.test(name)) {
    return {
      valid: false,
      error: 'Secret name must contain only letters, numbers, hyphens, and underscores',
    };
  }

  if (name.length > 100) {
    return { valid: false, error: 'Secret name must be 100 characters or less' };
  }

  return { valid: true };
}
