/**
 * Simple key storage for demo purposes
 * Stores keys in a local JSON file
 */

import { readFile, writeFile, mkdir } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { webcrypto } from 'node:crypto';
import { importJWK, exportJWK, type JWK } from 'jose';

const STORAGE_DIR = join(process.cwd(), '.demo-keys');
const STORAGE_FILE = join(STORAGE_DIR, 'client-keys.json');

interface StoredKeys {
  clientId: string;
  kid: string;
  publicJWK: JWK;
  privateJWK: JWK;
}

/**
 * Save keys to storage
 */
export async function saveKeys(
  clientId: string,
  kid: string,
  publicKey: webcrypto.CryptoKey,
  privateKey: webcrypto.CryptoKey
): Promise<void> {
  // Ensure storage directory exists
  if (!existsSync(STORAGE_DIR)) {
    await mkdir(STORAGE_DIR, { recursive: true });
  }

  // Export keys to JWK format
  const publicJWK = await exportJWK(publicKey);
  const privateJWK = await exportJWK(privateKey);

  const stored: StoredKeys = {
    clientId,
    kid,
    publicJWK,
    privateJWK,
  };

  await writeFile(STORAGE_FILE, JSON.stringify(stored, null, 2), 'utf-8');
  console.log(`\n💾 Keys saved to ${STORAGE_FILE}`);
}

/**
 * Load keys from storage
 */
export async function loadKeys(): Promise<{
  clientId: string;
  kid: string;
  publicKey: webcrypto.CryptoKey;
  privateKey: webcrypto.CryptoKey;
  publicJWK: JWK;
} | null> {
  if (!existsSync(STORAGE_FILE)) {
    return null;
  }

  const data = await readFile(STORAGE_FILE, 'utf-8');
  const stored: StoredKeys = JSON.parse(data);

  // Import keys from JWK using webcrypto directly
  const publicKey = await webcrypto.subtle.importKey(
    'jwk',
    stored.publicJWK as any,
    {
      name: 'Ed25519',
      namedCurve: 'Ed25519',
    } as any,
    true,
    ['verify']
  );

  const privateKey = await webcrypto.subtle.importKey(
    'jwk',
    stored.privateJWK as any,
    {
      name: 'Ed25519',
      namedCurve: 'Ed25519',
    } as any,
    true,
    ['sign']
  );

  return {
    clientId: stored.clientId,
    kid: stored.kid,
    publicKey,
    privateKey,
    publicJWK: stored.publicJWK,
  };
}

/**
 * Check if keys exist
 */
export function keysExist(): boolean {
  return existsSync(STORAGE_FILE);
}
