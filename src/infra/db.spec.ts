import { db } from './db.js';

describe('In-memory Database', () => {
  beforeEach(() => {
    db.clear();
  });

  describe('Client operations', () => {
    it('should create a client', () => {
      const client = db.createClient('test-client');

      expect(client.id).toBeDefined();
      expect(client.name).toBe('test-client');
      expect(client.createdAt).toBeInstanceOf(Date);
    });

    it('should retrieve a client by id', () => {
      const created = db.createClient('test-client');
      const retrieved = db.getClient(created.id);

      expect(retrieved).toEqual(created);
    });

    it('should return undefined for non-existent client', () => {
      const client = db.getClient('non-existent');

      expect(client).toBeUndefined();
    });

    it('should get all clients', () => {
      db.createClient('client-1');
      db.createClient('client-2');
      db.createClient('client-3');

      const clients = db.getAllClients();

      expect(clients).toHaveLength(3);
    });

    it('should generate unique client IDs', () => {
      const client1 = db.createClient('test');
      const client2 = db.createClient('test');

      expect(client1.id).not.toBe(client2.id);
    });
  });

  describe('Key operations', () => {
    it('should create a key record', () => {
      const client = db.createClient('test-client');
      const key = db.createKey({
        kid: 'key-001',
        clientId: client.id,
        jwk: { kty: 'OKP', crv: 'Ed25519', x: 'test' },
        algorithm: 'EdDSA',
        status: 'active',
      });

      expect(key.kid).toBe('key-001');
      expect(key.clientId).toBe(client.id);
      expect(key.status).toBe('active');
      expect(key.createdAt).toBeInstanceOf(Date);
    });

    it('should retrieve a key by kid', () => {
      const client = db.createClient('test-client');
      const created = db.createKey({
        kid: 'key-001',
        clientId: client.id,
        jwk: { kty: 'OKP', crv: 'Ed25519', x: 'test' },
        algorithm: 'EdDSA',
        status: 'active',
      });

      const retrieved = db.getKey('key-001');

      expect(retrieved).toEqual(created);
    });

    it('should get keys by client', () => {
      const client = db.createClient('test-client');
      db.createKey({
        kid: 'key-001',
        clientId: client.id,
        jwk: { kty: 'OKP', crv: 'Ed25519', x: 'test1' },
        algorithm: 'EdDSA',
        status: 'active',
      });
      db.createKey({
        kid: 'key-002',
        clientId: client.id,
        jwk: { kty: 'OKP', crv: 'Ed25519', x: 'test2' },
        algorithm: 'EdDSA',
        status: 'active',
      });

      const keys = db.getKeysByClient(client.id);

      expect(keys).toHaveLength(2);
    });

    it('should revoke a key', () => {
      const client = db.createClient('test-client');
      db.createKey({
        kid: 'key-001',
        clientId: client.id,
        jwk: { kty: 'OKP', crv: 'Ed25519', x: 'test' },
        algorithm: 'EdDSA',
        status: 'active',
      });

      const revoked = db.revokeKey('key-001');
      const key = db.getKey('key-001');

      expect(revoked).toBe(true);
      expect(key?.status).toBe('revoked');
    });

    it('should return false when revoking non-existent key', () => {
      const revoked = db.revokeKey('non-existent');

      expect(revoked).toBe(false);
    });
  });

  describe('Audit operations', () => {
    it('should add audit entry', () => {
      const entry = db.addAuditEntry({
        clientId: 'client-123',
        kid: 'key-001',
        result: 'ok',
        coveredComponents: ['@method', '@target-uri', 'content-digest'],
        endpoint: '/v1/secrets/test',
        method: 'PUT',
      });

      expect(entry.id).toBeDefined();
      expect(entry.timestamp).toBeInstanceOf(Date);
      expect(entry.result).toBe('ok');
    });

    it('should get audit log', () => {
      db.addAuditEntry({
        clientId: 'client-123',
        kid: 'key-001',
        result: 'ok',
        coveredComponents: ['@method'],
        endpoint: '/test',
        method: 'GET',
      });
      db.addAuditEntry({
        clientId: 'client-123',
        kid: 'key-001',
        result: 'fail',
        reason: 'digest_mismatch',
        coveredComponents: ['@method'],
        endpoint: '/test',
        method: 'POST',
      });

      const log = db.getAuditLog();

      expect(log).toHaveLength(2);
    });

    it('should limit audit log entries', () => {
      for (let i = 0; i < 10; i++) {
        db.addAuditEntry({
          clientId: 'client-123',
          kid: 'key-001',
          result: 'ok',
          coveredComponents: ['@method'],
          endpoint: '/test',
          method: 'GET',
        });
      }

      const log = db.getAuditLog(5);

      expect(log).toHaveLength(5);
    });

    it('should return audit log in reverse chronological order', async () => {
      const entry1 = db.addAuditEntry({
        clientId: 'client-123',
        kid: 'key-001',
        result: 'ok',
        coveredComponents: ['@method'],
        endpoint: '/test1',
        method: 'GET',
      });

      // Wait to ensure different timestamps
      await new Promise(resolve => setTimeout(resolve, 10));

      const entry2 = db.addAuditEntry({
        clientId: 'client-123',
        kid: 'key-001',
        result: 'ok',
        coveredComponents: ['@method'],
        endpoint: '/test2',
        method: 'GET',
      });

      const log = db.getAuditLog();

      expect(log[0].id).toBe(entry2.id);
      expect(log[1].id).toBe(entry1.id);
    });

    it('should get audit entries by client', () => {
      db.addAuditEntry({
        clientId: 'client-1',
        kid: 'key-001',
        result: 'ok',
        coveredComponents: ['@method'],
        endpoint: '/test',
        method: 'GET',
      });
      db.addAuditEntry({
        clientId: 'client-2',
        kid: 'key-002',
        result: 'ok',
        coveredComponents: ['@method'],
        endpoint: '/test',
        method: 'GET',
      });

      const log = db.getAuditByClient('client-1');

      expect(log).toHaveLength(1);
      expect(log[0].clientId).toBe('client-1');
    });
  });

  describe('Secret operations', () => {
    it('should create a secret', () => {
      const secret = db.createSecret('db-password', 'secret123', [
        'client-1',
        'client-2',
      ]);

      expect(secret.name).toBe('db-password');
      expect(secret.value).toBe('secret123');
      expect(secret.allowedClientIds).toEqual(['client-1', 'client-2']);
      expect(secret.createdAt).toBeInstanceOf(Date);
      expect(secret.updatedAt).toBeInstanceOf(Date);
    });

    it('should retrieve a secret', () => {
      db.createSecret('api-key', 'key123', ['client-1']);
      const secret = db.getSecret('api-key');

      expect(secret?.value).toBe('key123');
    });

    it('should update a secret', () => {
      db.createSecret('password', 'old-pass', ['client-1']);
      const updated = db.updateSecret('password', 'new-pass');

      expect(updated?.value).toBe('new-pass');
      expect(updated?.updatedAt).toBeInstanceOf(Date);
    });

    it('should return undefined when updating non-existent secret', () => {
      const updated = db.updateSecret('non-existent', 'value');

      expect(updated).toBeUndefined();
    });

    it('should delete a secret', () => {
      db.createSecret('temp', 'value', []);
      const deleted = db.deleteSecret('temp');
      const retrieved = db.getSecret('temp');

      expect(deleted).toBe(true);
      expect(retrieved).toBeUndefined();
    });

    it('should check client authorization', () => {
      db.createSecret('secret', 'value', ['client-1', 'client-2']);

      expect(db.isClientAuthorizedForSecret('client-1', 'secret')).toBe(true);
      expect(db.isClientAuthorizedForSecret('client-3', 'secret')).toBe(false);
    });

    it('should authorize client for secret', () => {
      db.createSecret('secret', 'value', ['client-1']);

      db.authorizeClientForSecret('client-2', 'secret');

      expect(db.isClientAuthorizedForSecret('client-2', 'secret')).toBe(true);
    });

    it('should not duplicate client in allowedClientIds', () => {
      db.createSecret('secret', 'value', ['client-1']);

      db.authorizeClientForSecret('client-1', 'secret');
      db.authorizeClientForSecret('client-1', 'secret');

      const secret = db.getSecret('secret');
      const count = secret?.allowedClientIds.filter((id) => id === 'client-1')
        .length;

      expect(count).toBe(1);
    });
  });

  describe('Utility operations', () => {
    it('should get database stats', () => {
      db.createClient('client-1');
      db.createClient('client-2');
      const client = db.createClient('client-3');

      db.createKey({
        kid: 'key-001',
        clientId: client.id,
        jwk: { kty: 'OKP', crv: 'Ed25519', x: 'test' },
        algorithm: 'EdDSA',
        status: 'active',
      });

      db.createSecret('secret', 'value', [client.id]);

      db.addAuditEntry({
        clientId: client.id,
        kid: 'key-001',
        result: 'ok',
        coveredComponents: ['@method'],
        endpoint: '/test',
        method: 'GET',
      });

      const stats = db.getStats();

      expect(stats.clients).toBe(3);
      expect(stats.keys).toBe(1);
      expect(stats.secrets).toBe(1);
      expect(stats.auditEntries).toBe(1);
    });

    it('should clear all data', () => {
      db.createClient('client');
      db.createSecret('secret', 'value', []);

      db.clear();

      const stats = db.getStats();

      expect(stats.clients).toBe(0);
      expect(stats.keys).toBe(0);
      expect(stats.secrets).toBe(0);
      expect(stats.auditEntries).toBe(0);
    });
  });
});
