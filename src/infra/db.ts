/**
 * In-memory data stores for demo
 *
 * This module provides simple in-memory storage for clients, keys, audit logs,
 * and secrets. In production, these would be replaced with a real database.
 */

import type { JWK } from 'jose';

export interface ClientRecord {
  id: string;
  name: string;
  createdAt: Date;
}

export interface KeyRecord {
  kid: string;
  clientId: string;
  jwk: JWK;
  algorithm: string; // e.g., "EdDSA", "ES256"
  status: 'active' | 'revoked';
  createdAt: Date;
}

export interface AuditEntry {
  id: string;
  timestamp: Date;
  clientId: string;
  kid: string;
  result: 'ok' | 'fail';
  reason?: string;
  coveredComponents: string[];
  endpoint: string;
  method: string;
}

export interface SecretValue {
  name: string;
  value: string;
  allowedClientIds: string[];
  createdAt: Date;
  updatedAt: Date;
}

export interface NonceRecord {
  nonce: string;
  expiresAt: Date;
  usedAt: Date;
  clientId: string;
  kid: string;
}

/**
 * In-memory database
 */
class Database {
  private clients = new Map<string, ClientRecord>();
  private keys = new Map<string, KeyRecord>();
  private audit: AuditEntry[] = [];
  private secrets = new Map<string, SecretValue>();
  private nonces = new Map<string, NonceRecord>();
  private cleanupInterval: NodeJS.Timeout | null = null;

  // Client operations
  createClient(name: string): ClientRecord {
    const client: ClientRecord = {
      id: `client-${Date.now()}-${Math.random().toString(36).substring(7)}`,
      name,
      createdAt: new Date(),
    };

    this.clients.set(client.id, client);
    return client;
  }

  getClient(id: string): ClientRecord | undefined {
    return this.clients.get(id);
  }

  getAllClients(): ClientRecord[] {
    return Array.from(this.clients.values());
  }

  // Key operations
  createKey(keyRecord: Omit<KeyRecord, 'createdAt'>): KeyRecord {
    const key: KeyRecord = {
      ...keyRecord,
      createdAt: new Date(),
    };

    this.keys.set(key.kid, key);
    return key;
  }

  getKey(kid: string): KeyRecord | undefined {
    return this.keys.get(kid);
  }

  getKeysByClient(clientId: string): KeyRecord[] {
    return Array.from(this.keys.values()).filter(
      (key) => key.clientId === clientId
    );
  }

  revokeKey(kid: string): boolean {
    const key = this.keys.get(kid);
    if (!key) {
      return false;
    }

    key.status = 'revoked';
    return true;
  }

  // Audit operations
  addAuditEntry(entry: Omit<AuditEntry, 'id' | 'timestamp'>): AuditEntry {
    const auditEntry: AuditEntry = {
      id: `audit-${Date.now()}-${Math.random().toString(36).substring(7)}`,
      timestamp: new Date(),
      ...entry,
    };

    this.audit.push(auditEntry);
    return auditEntry;
  }

  getAuditLog(limit?: number): AuditEntry[] {
    const entries = [...this.audit].sort(
      (a, b) => b.timestamp.getTime() - a.timestamp.getTime()
    );

    return limit ? entries.slice(0, limit) : entries;
  }

  getAuditByClient(clientId: string, limit?: number): AuditEntry[] {
    const entries = this.audit
      .filter((entry) => entry.clientId === clientId)
      .sort((a, b) => b.timestamp.getTime() - a.timestamp.getTime());

    return limit ? entries.slice(0, limit) : entries;
  }

  // Secret operations
  createSecret(
    name: string,
    value: string,
    allowedClientIds: string[]
  ): SecretValue {
    const secret: SecretValue = {
      name,
      value,
      allowedClientIds,
      createdAt: new Date(),
      updatedAt: new Date(),
    };

    this.secrets.set(name, secret);
    return secret;
  }

  getSecret(name: string): SecretValue | undefined {
    return this.secrets.get(name);
  }

  updateSecret(name: string, value: string): SecretValue | undefined {
    const secret = this.secrets.get(name);
    if (!secret) {
      return undefined;
    }

    secret.value = value;
    secret.updatedAt = new Date();
    return secret;
  }

  deleteSecret(name: string): boolean {
    return this.secrets.delete(name);
  }

  isClientAuthorizedForSecret(clientId: string, secretName: string): boolean {
    const secret = this.secrets.get(secretName);
    if (!secret) {
      return false;
    }

    return secret.allowedClientIds.includes(clientId);
  }

  authorizeClientForSecret(clientId: string, secretName: string): boolean {
    const secret = this.secrets.get(secretName);
    if (!secret) {
      return false;
    }

    if (!secret.allowedClientIds.includes(clientId)) {
      secret.allowedClientIds.push(clientId);
    }

    return true;
  }

  // Nonce operations for replay protection
  constructor() {
    // Start periodic cleanup of expired nonces (every minute)
    this.cleanupInterval = setInterval(() => {
      this.cleanupExpiredNonces();
    }, 60 * 1000);
  }

  /**
   * Check if a nonce has been used before
   * Returns true if nonce was already used (replay detected)
   */
  isNonceUsed(nonce: string): boolean {
    const record = this.nonces.get(nonce);
    if (!record) {
      return false;
    }

    // If nonce exists and hasn't expired yet, it's a replay
    const now = new Date();
    return record.expiresAt > now;
  }

  /**
   * Store a nonce to prevent replay
   */
  storeNonce(nonce: string, expiresAt: Date, clientId: string, kid: string): void {
    const record: NonceRecord = {
      nonce,
      expiresAt,
      usedAt: new Date(),
      clientId,
      kid,
    };

    this.nonces.set(nonce, record);
  }

  /**
   * Clean up expired nonces to prevent memory bloat
   */
  private cleanupExpiredNonces(): void {
    const now = new Date();
    const toDelete: string[] = [];

    for (const [nonce, record] of this.nonces.entries()) {
      if (record.expiresAt <= now) {
        toDelete.push(nonce);
      }
    }

    for (const nonce of toDelete) {
      this.nonces.delete(nonce);
    }

    if (toDelete.length > 0) {
      console.log(`🧹 Cleaned up ${toDelete.length} expired nonces`);
    }
  }

  /**
   * Get nonce statistics
   */
  getNonceStats(): { total: number; expired: number } {
    const now = new Date();
    let expired = 0;

    for (const record of this.nonces.values()) {
      if (record.expiresAt <= now) {
        expired++;
      }
    }

    return {
      total: this.nonces.size,
      expired,
    };
  }

  // Utility methods for demo
  clear(): void {
    this.clients.clear();
    this.keys.clear();
    this.audit = [];
    this.secrets.clear();
    this.nonces.clear();
  }

  getStats(): {
    clients: number;
    keys: number;
    auditEntries: number;
    secrets: number;
    nonces: number;
  } {
    return {
      clients: this.clients.size,
      keys: this.keys.size,
      auditEntries: this.audit.length,
      secrets: this.secrets.size,
      nonces: this.nonces.size,
    };
  }

  /**
   * Clean up resources
   */
  shutdown(): void {
    if (this.cleanupInterval) {
      clearInterval(this.cleanupInterval);
      this.cleanupInterval = null;
    }
  }
}

// Export a singleton instance
export const db = new Database();
