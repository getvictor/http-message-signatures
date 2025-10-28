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

/**
 * In-memory database
 */
class Database {
  private clients = new Map<string, ClientRecord>();
  private keys = new Map<string, KeyRecord>();
  private audit: AuditEntry[] = [];
  private secrets = new Map<string, SecretValue>();

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

  // Utility methods for demo
  clear(): void {
    this.clients.clear();
    this.keys.clear();
    this.audit = [];
    this.secrets.clear();
  }

  getStats(): {
    clients: number;
    keys: number;
    auditEntries: number;
    secrets: number;
  } {
    return {
      clients: this.clients.size,
      keys: this.keys.size,
      auditEntries: this.audit.length,
      secrets: this.secrets.size,
    };
  }
}

// Export a singleton instance
export const db = new Database();
