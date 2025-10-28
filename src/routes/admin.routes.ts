/**
 * Admin routes for client and key management
 * These endpoints do NOT require signature verification (bootstrap endpoints)
 */

import { Router, type Request, type Response } from 'express';
import { db } from '../infra/db.js';
import { HttpErrors } from '../shared/errors.js';
import {
  validateClientRequest,
  validateKeyRequest,
} from '../shared/schemas.js';
import { ensureKid } from '../crypto/kid.js';

const router = Router();

/**
 * POST /admin/clients
 * Create a new client
 */
router.post('/clients', async (req: Request, res: Response) => {
  const validation = validateClientRequest(req.body);

  if (!validation.valid) {
    return res.status(400).json(HttpErrors.badRequest(validation.error!));
  }

  const client = db.createClient(validation.data!.name);

  req.log.info({ clientId: client.id }, 'Client created');

  res.status(201).json({
    id: client.id,
    name: client.name,
    createdAt: client.createdAt.toISOString(),
  });
});

/**
 * GET /admin/clients
 * List all clients
 */
router.get('/clients', (req: Request, res: Response) => {
  const clients = db.getAllClients();

  res.json({
    clients: clients.map((c) => ({
      id: c.id,
      name: c.name,
      createdAt: c.createdAt.toISOString(),
    })),
    total: clients.length,
  });
});

/**
 * GET /admin/clients/:id
 * Get client details
 */
router.get('/clients/:id', (req: Request, res: Response) => {
  const client = db.getClient(req.params.id);

  if (!client) {
    return res.status(404).json(HttpErrors.notFound('Client not found'));
  }

  const keys = db.getKeysByClient(client.id);

  res.json({
    id: client.id,
    name: client.name,
    createdAt: client.createdAt.toISOString(),
    keys: keys.map((k) => ({
      kid: k.kid,
      algorithm: k.algorithm,
      status: k.status,
      createdAt: k.createdAt.toISOString(),
    })),
  });
});

/**
 * POST /admin/clients/:id/keys
 * Register a public key for a client
 */
router.post('/clients/:id/keys', async (req: Request, res: Response) => {
  const client = db.getClient(req.params.id);

  if (!client) {
    return res.status(404).json(HttpErrors.notFound('Client not found'));
  }

  const validation = validateKeyRequest(req.body);

  if (!validation.valid) {
    return res.status(400).json(HttpErrors.badRequest(validation.error!));
  }

  const { kid, jwk, algorithm } = validation.data!;

  // Check if kid already exists
  const existingKey = db.getKey(kid);
  if (existingKey) {
    return res
      .status(409)
      .json(HttpErrors.conflict(`Key ID "${kid}" already exists`));
  }

  // Ensure JWK has kid field
  const jwkWithKid = await ensureKid(jwk);

  // Store the key
  const keyRecord = db.createKey({
    kid,
    clientId: client.id,
    jwk: jwkWithKid,
    algorithm,
    status: 'active',
  });

  req.log.info(
    { clientId: client.id, kid },
    'Public key registered for client'
  );

  res.status(201).json({
    kid: keyRecord.kid,
    algorithm: keyRecord.algorithm,
    status: keyRecord.status,
    createdAt: keyRecord.createdAt.toISOString(),
  });
});

/**
 * GET /admin/keys/:kid
 * Get key details
 */
router.get('/keys/:kid', (req: Request, res: Response) => {
  const key = db.getKey(req.params.kid);

  if (!key) {
    return res.status(404).json(HttpErrors.notFound('Key not found'));
  }

  const client = db.getClient(key.clientId);

  res.json({
    kid: key.kid,
    clientId: key.clientId,
    clientName: client?.name,
    algorithm: key.algorithm,
    status: key.status,
    jwk: key.jwk,
    createdAt: key.createdAt.toISOString(),
  });
});

/**
 * POST /admin/keys/:kid/revoke
 * Revoke a key
 */
router.post('/keys/:kid/revoke', (req: Request, res: Response) => {
  const key = db.getKey(req.params.kid);

  if (!key) {
    return res.status(404).json(HttpErrors.notFound('Key not found'));
  }

  if (key.status === 'revoked') {
    return res.status(409).json(HttpErrors.conflict('Key is already revoked'));
  }

  db.revokeKey(req.params.kid);

  req.log.info({ kid: req.params.kid }, 'Key revoked');

  res.json({
    kid: key.kid,
    status: 'revoked',
    message: 'Key has been revoked',
  });
});

/**
 * GET /admin/audit
 * Get audit log
 */
router.get('/audit', (req: Request, res: Response) => {
  const limit = req.query.limit ? parseInt(req.query.limit as string, 10) : 100;

  if (isNaN(limit) || limit < 1 || limit > 1000) {
    return res
      .status(400)
      .json(HttpErrors.badRequest('Limit must be between 1 and 1000'));
  }

  const entries = db.getAuditLog(limit);

  res.json({
    entries: entries.map((e) => ({
      id: e.id,
      timestamp: e.timestamp.toISOString(),
      clientId: e.clientId,
      kid: e.kid,
      result: e.result,
      reason: e.reason,
      coveredComponents: e.coveredComponents,
      endpoint: e.endpoint,
      method: e.method,
    })),
    total: entries.length,
  });
});

/**
 * GET /admin/audit/client/:clientId
 * Get audit log for a specific client
 */
router.get('/audit/client/:clientId', (req: Request, res: Response) => {
  const limit = req.query.limit ? parseInt(req.query.limit as string, 10) : 100;

  if (isNaN(limit) || limit < 1 || limit > 1000) {
    return res
      .status(400).json(HttpErrors.badRequest('Limit must be between 1 and 1000'));
  }

  const entries = db.getAuditByClient(req.params.clientId, limit);

  res.json({
    clientId: req.params.clientId,
    entries: entries.map((e) => ({
      id: e.id,
      timestamp: e.timestamp.toISOString(),
      kid: e.kid,
      result: e.result,
      reason: e.reason,
      coveredComponents: e.coveredComponents,
      endpoint: e.endpoint,
      method: e.method,
    })),
    total: entries.length,
  });
});

export default router;
