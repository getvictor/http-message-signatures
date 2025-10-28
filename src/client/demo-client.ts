/**
 * Demo client for HTTP Message Signatures
 * Demonstrates enrollment, good requests, and bad requests (tampered)
 */

import { webcrypto } from 'node:crypto';
import { exportJWK, type JWK } from 'jose';
import { httpbis } from 'http-message-signatures';
import type { Request as SignRequest } from 'http-message-signatures/lib/types';
import { computeDigest } from '../crypto/digest.js';

const BASE_URL = process.env.BASE_URL || 'http://localhost:3000';

interface ClientKeys {
  kid: string;
  publicKey: webcrypto.CryptoKey;
  privateKey: webcrypto.CryptoKey;
  publicJWK: JWK;
}

/**
 * Generate Ed25519 key pair for the demo client
 */
export async function generateKeyPair(): Promise<ClientKeys> {
  // Generate Ed25519 key pair using Web Crypto API
  const keyPair = await webcrypto.subtle.generateKey(
    {
      name: 'Ed25519',
      namedCurve: 'Ed25519',
    } as any, // TypeScript doesn't have full Ed25519 types yet
    true, // extractable
    ['sign', 'verify']
  );

  // Export public key as JWK
  const publicJWK = await exportJWK(keyPair.publicKey);

  // Generate key ID from public key (simple hash for demo)
  const encoder = new TextEncoder();
  const jwkString = JSON.stringify(publicJWK);
  const jwkHash = await webcrypto.subtle.digest('SHA-256', encoder.encode(jwkString));
  const kid = Buffer.from(jwkHash).toString('hex').substring(0, 16);

  return {
    kid,
    publicKey: keyPair.publicKey,
    privateKey: keyPair.privateKey,
    publicJWK,
  };
}

/**
 * Enroll the client with the server
 * 1. Create client
 * 2. Register public key
 */
export async function enrollClient(clientName: string, keys: ClientKeys): Promise<string> {
  console.log('\n🔐 Enrolling client...');

  // Step 1: Create client
  console.log(`  → Creating client "${clientName}"...`);
  const createClientRes = await fetch(`${BASE_URL}/admin/clients`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ name: clientName }),
  });

  if (!createClientRes.ok) {
    const error = await createClientRes.json();
    throw new Error(`Failed to create client: ${JSON.stringify(error)}`);
  }

  const clientData = (await createClientRes.json()) as { id: string; name: string; createdAt: string };
  const clientId = clientData.id;
  console.log(`  ✓ Client created: ${clientId}`);

  // Step 2: Register public key
  console.log(`  → Registering public key (kid: ${keys.kid})...`);
  const registerKeyRes = await fetch(`${BASE_URL}/admin/clients/${clientId}/keys`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      kid: keys.kid,
      jwk: keys.publicJWK,
      alg: 'EdDSA',
    }),
  });

  if (!registerKeyRes.ok) {
    const error = await registerKeyRes.json();
    throw new Error(`Failed to register key: ${JSON.stringify(error)}`);
  }

  console.log(`  ✓ Public key registered`);
  console.log(`\n✅ Enrollment complete!`);
  console.log(`   Client ID: ${clientId}`);
  console.log(`   Key ID: ${keys.kid}\n`);

  return clientId;
}

/**
 * Sign and send a request to the server
 */
export async function signAndSendRequest(
  keys: ClientKeys,
  method: string,
  path: string,
  body?: any,
  tamper: boolean = false
): Promise<Response> {
  const url = `${BASE_URL}${path}`;
  const bodyString = body ? JSON.stringify(body) : undefined;

  console.log(`\n📤 ${method} ${path}`);
  if (bodyString) {
    console.log(`   Body: ${bodyString}`);
  }

  // Compute Content-Digest for the body
  let contentDigest: string | undefined;
  if (bodyString) {
    contentDigest = computeDigest(bodyString, 'sha-256');
    console.log(`   Content-Digest: ${contentDigest}`);
  }

  // Prepare the message object for signing
  const message: SignRequest & { body?: string } = {
    method: method.toUpperCase(),
    url,
    headers: {
      'content-type': 'application/json',
    },
  };

  if (contentDigest) {
    message.headers['content-digest'] = contentDigest;
  }

  if (bodyString) {
    message.body = bodyString;
  }

  // Create signer function
  const signer = async (data: Buffer): Promise<Buffer> => {
    const signature = await webcrypto.subtle.sign('Ed25519', keys.privateKey, data);
    return Buffer.from(signature);
  };

  // Sign the message
  console.log(`   🔏 Signing request...`);
  const signedMessage = await httpbis.signMessage(
    {
      key: {
        id: keys.kid,
        alg: 'ed25519',
        sign: signer,
      },
      fields: contentDigest
        ? ['@method', '@target-uri', 'content-type', 'content-digest']
        : ['@method', '@target-uri'],
      paramValues: {
        created: new Date(),
        expires: new Date(Date.now() + 5 * 60 * 1000), // 5 minutes
      },
    },
    message
  );

  const signature = signedMessage.headers['signature'] || signedMessage.headers['Signature'];
  const signatureInput = signedMessage.headers['signature-input'] || signedMessage.headers['Signature-Input'];

  console.log(`   ✓ Signature generated`);
  console.log(`   Signature: ${signature}`);
  console.log(`   Signature-Input: ${signatureInput}`);

  if (!signature || !signatureInput) {
    throw new Error('Failed to generate signature headers');
  }

  // Prepare fetch headers
  const fetchHeaders: Record<string, string> = {
    'Content-Type': 'application/json',
    'Signature': signature as string,
    'Signature-Input': signatureInput as string,
  };

  if (contentDigest) {
    fetchHeaders['Content-Digest'] = contentDigest;
  }

  // Tamper with body if requested (for bad request demo)
  let sendBody = bodyString;
  if (tamper && bodyString) {
    const tamperedData = JSON.parse(bodyString);
    // Change the value to simulate tampering
    if (tamperedData.value) {
      tamperedData.value = 'TAMPERED_' + tamperedData.value;
    }
    sendBody = JSON.stringify(tamperedData);
    console.log(`   ⚠️  TAMPERING: Changed body to ${sendBody}`);
    console.log(`   ⚠️  Content-Digest no longer matches!`);
  }

  // Send the request
  console.log(`   → Sending request...`);
  const response = await fetch(url, {
    method,
    headers: fetchHeaders,
    body: sendBody,
  });

  console.log(`   ← Response: ${response.status} ${response.statusText}`);

  return response;
}

/**
 * Demo: Good request (properly signed)
 */
export async function demoGoodRequest(keys: ClientKeys): Promise<void> {
  console.log('\n' + '='.repeat(60));
  console.log('✅ DEMO: Good Request (Properly Signed)');
  console.log('='.repeat(60));

  const secretName = 'demo-secret';
  const secretValue = 'my-super-secret-value';

  // Store a secret
  const response = await signAndSendRequest(
    keys,
    'PUT',
    `/v1/secrets/${secretName}`,
    { value: secretValue },
    false // Don't tamper
  );

  const result = await response.json();
  console.log(`\n📋 Response:`);
  console.log(JSON.stringify(result, null, 2));

  if (response.ok) {
    console.log(`\n✅ SUCCESS: Request was accepted!`);
    console.log(`   The signature verification passed.`);
    console.log(`   The Content-Digest matched the body.`);
  } else {
    console.log(`\n❌ FAILED: Request was rejected!`);
  }
}

/**
 * Demo: Bad request (tampered body)
 */
export async function demoBadRequest(keys: ClientKeys): Promise<void> {
  console.log('\n' + '='.repeat(60));
  console.log('❌ DEMO: Bad Request (Tampered Body)');
  console.log('='.repeat(60));

  const secretName = 'tampered-secret';
  const secretValue = 'original-value';

  console.log('\nℹ️  This demo shows what happens when the request body is');
  console.log('   tampered with after signing. The Content-Digest will no');
  console.log('   longer match, and the server will reject the request.');

  // Try to store a secret with tampered body
  const response = await signAndSendRequest(
    keys,
    'PUT',
    `/v1/secrets/${secretName}`,
    { value: secretValue },
    true // Tamper with body!
  );

  const result = await response.json();
  console.log(`\n📋 Response:`);
  console.log(JSON.stringify(result, null, 2));

  if (!response.ok) {
    console.log(`\n✅ EXPECTED: Request was rejected!`);
    console.log(`   The server detected the tampered body.`);
    console.log(`   The Content-Digest verification failed.`);
  } else {
    console.log(`\n⚠️  UNEXPECTED: Request was accepted (should have been rejected)`);
  }
}

/**
 * Main enrollment demo
 */
export async function runEnrollmentDemo(): Promise<{ clientId: string; keys: ClientKeys }> {
  console.log('╔' + '═'.repeat(58) + '╗');
  console.log('║' + ' '.repeat(10) + 'HTTP Message Signatures Demo' + ' '.repeat(20) + '║');
  console.log('║' + ' '.repeat(18) + 'Phase 1: Enrollment' + ' '.repeat(21) + '║');
  console.log('╚' + '═'.repeat(58) + '╝');

  // Generate keys
  console.log('\n🔑 Generating Ed25519 key pair...');
  const keys = await generateKeyPair();
  console.log(`   ✓ Key pair generated`);
  console.log(`   Key ID: ${keys.kid}`);

  // Enroll with server
  const clientId = await enrollClient('demo-client', keys);

  return { clientId, keys };
}

/**
 * Main good request demo
 */
export async function runGoodRequestDemo(keys: ClientKeys): Promise<void> {
  console.log('\n╔' + '═'.repeat(58) + '╗');
  console.log('║' + ' '.repeat(10) + 'HTTP Message Signatures Demo' + ' '.repeat(20) + '║');
  console.log('║' + ' '.repeat(15) + 'Phase 2: Good Request' + ' '.repeat(22) + '║');
  console.log('╚' + '═'.repeat(58) + '╝');

  await demoGoodRequest(keys);
}

/**
 * Main bad request demo
 */
export async function runBadRequestDemo(keys: ClientKeys): Promise<void> {
  console.log('\n╔' + '═'.repeat(58) + '╗');
  console.log('║' + ' '.repeat(10) + 'HTTP Message Signatures Demo' + ' '.repeat(20) + '║');
  console.log('║' + ' '.repeat(16) + 'Phase 3: Bad Request' + ' '.repeat(22) + '║');
  console.log('╚' + '═'.repeat(58) + '╝');

  await demoBadRequest(keys);
}
