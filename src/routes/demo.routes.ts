/**
 * Demo API routes - Secrets management
 * These endpoints REQUIRE signature verification
 */

import { Router, type Request, type Response } from 'express';
import { db } from '../infra/db.js';
import { HttpErrors } from '../shared/errors.js';
import {
  validateSecretRequest,
  validateSecretName,
} from '../shared/schemas.js';

const router = Router();

/**
 * PUT /v1/secrets/:name
 * Store or update a secret
 * Requires: Signature verification (via middleware)
 */
router.put('/secrets/:name', (req: Request, res: Response) => {
  // req.identity is set by the signature verification middleware
  if (!req.identity) {
    return res.status(401).json(HttpErrors.unauthorized('Authentication required'));
  }

  // Validate secret name
  const nameValidation = validateSecretName(req.params.name);
  if (!nameValidation.valid) {
    return res.status(400).json(HttpErrors.badRequest(nameValidation.error!));
  }

  // Validate secret value
  const validation = validateSecretRequest(req.body);
  if (!validation.valid) {
    return res.status(400).json(HttpErrors.badRequest(validation.error!));
  }

  const secretName = req.params.name;
  const { value } = validation.data!;
  const { clientId } = req.identity;

  // Check if secret already exists
  const existingSecret = db.getSecret(secretName);

  if (existingSecret) {
    // Update existing secret
    // Only the creator or authorized clients can update
    if (!db.isClientAuthorizedForSecret(clientId, secretName)) {
      // Auto-authorize the creator
      db.authorizeClientForSecret(clientId, secretName);
    }

    db.updateSecret(secretName, value);

    req.log.info(
      { clientId, secretName },
      'Secret updated'
    );

    return res.json({
      name: secretName,
      status: 'updated',
      message: 'Secret has been updated',
    });
  } else {
    // Create new secret
    db.createSecret(secretName, value, [clientId]);

    req.log.info(
      { clientId, secretName },
      'Secret created'
    );

    return res.status(201).json({
      name: secretName,
      status: 'created',
      message: 'Secret has been created',
    });
  }
});

/**
 * GET /v1/secrets/:name
 * Retrieve a secret
 * Requires: Signature verification (via middleware)
 */
router.get('/secrets/:name', (req: Request, res: Response) => {
  // req.identity is set by the signature verification middleware
  if (!req.identity) {
    return res.status(401).json(HttpErrors.unauthorized('Authentication required'));
  }

  // Validate secret name
  const nameValidation = validateSecretName(req.params.name);
  if (!nameValidation.valid) {
    return res.status(400).json(HttpErrors.badRequest(nameValidation.error!));
  }

  const secretName = req.params.name;
  const { clientId } = req.identity;

  // Check if secret exists
  const secret = db.getSecret(secretName);

  if (!secret) {
    return res.status(404).json(HttpErrors.notFound('Secret not found'));
  }

  // Check authorization
  if (!db.isClientAuthorizedForSecret(clientId, secretName)) {
    req.log.warn(
      { clientId, secretName },
      'Unauthorized access attempt to secret'
    );

    return res
      .status(403)
      .json(HttpErrors.forbidden('You are not authorized to access this secret'));
  }

  req.log.info(
    { clientId, secretName },
    'Secret retrieved'
  );

  res.json({
    name: secret.name,
    value: secret.value,
    createdAt: secret.createdAt.toISOString(),
    updatedAt: secret.updatedAt.toISOString(),
  });
});

/**
 * DELETE /v1/secrets/:name
 * Delete a secret
 * Requires: Signature verification (via middleware)
 */
router.delete('/secrets/:name', (req: Request, res: Response) => {
  // req.identity is set by the signature verification middleware
  if (!req.identity) {
    return res.status(401).json(HttpErrors.unauthorized('Authentication required'));
  }

  // Validate secret name
  const nameValidation = validateSecretName(req.params.name);
  if (!nameValidation.valid) {
    return res.status(400).json(HttpErrors.badRequest(nameValidation.error!));
  }

  const secretName = req.params.name;
  const { clientId } = req.identity;

  // Check if secret exists
  const secret = db.getSecret(secretName);

  if (!secret) {
    return res.status(404).json(HttpErrors.notFound('Secret not found'));
  }

  // Check authorization
  if (!db.isClientAuthorizedForSecret(clientId, secretName)) {
    req.log.warn(
      { clientId, secretName },
      'Unauthorized deletion attempt'
    );

    return res
      .status(403)
      .json(HttpErrors.forbidden('You are not authorized to delete this secret'));
  }

  db.deleteSecret(secretName);

  req.log.info(
    { clientId, secretName },
    'Secret deleted'
  );

  res.json({
    name: secretName,
    status: 'deleted',
    message: 'Secret has been deleted',
  });
});

/**
 * POST /v1/secrets/:name/authorize
 * Authorize another client to access a secret
 * Requires: Signature verification (via middleware)
 */
router.post('/secrets/:name/authorize', (req: Request, res: Response) => {
  // req.identity is set by the signature verification middleware
  if (!req.identity) {
    return res.status(401).json(HttpErrors.unauthorized('Authentication required'));
  }

  // Validate secret name
  const nameValidation = validateSecretName(req.params.name);
  if (!nameValidation.valid) {
    return res.status(400).json(HttpErrors.badRequest(nameValidation.error!));
  }

  const { targetClientId } = req.body;

  if (!targetClientId || typeof targetClientId !== 'string') {
    return res
      .status(400)
      .json(HttpErrors.badRequest('Field "targetClientId" is required'));
  }

  const secretName = req.params.name;
  const { clientId } = req.identity;

  // Check if secret exists
  const secret = db.getSecret(secretName);

  if (!secret) {
    return res.status(404).json(HttpErrors.notFound('Secret not found'));
  }

  // Check if requester is authorized
  if (!db.isClientAuthorizedForSecret(clientId, secretName)) {
    return res
      .status(403)
      .json(HttpErrors.forbidden('You are not authorized for this secret'));
  }

  // Check if target client exists
  const targetClient = db.getClient(targetClientId);
  if (!targetClient) {
    return res
      .status(404)
      .json(HttpErrors.notFound('Target client not found'));
  }

  // Authorize the target client
  db.authorizeClientForSecret(targetClientId, secretName);

  req.log.info(
    { clientId, secretName, targetClientId },
    'Client authorized for secret'
  );

  res.json({
    name: secretName,
    authorizedClient: targetClientId,
    message: 'Client has been authorized',
  });
});

export default router;
