#!/usr/bin/env node
/**
 * Demo script: Bad request (changed HTTP method)
 */

import { runBadRequestMethodChangeDemo } from './demo-client.js';
import { loadKeys } from './key-storage.js';

async function main() {
  try {
    // Load saved keys
    const savedKeys = await loadKeys();

    if (!savedKeys) {
      console.error('\n❌ No keys found!');
      console.error('   Please run enrollment first: npm run demo:enroll\n');
      process.exit(1);
    }

    console.log(`\n📌 Using saved keys (kid: ${savedKeys.kid})`);

    // Run bad request demo (method change attack)
    await runBadRequestMethodChangeDemo({
      kid: savedKeys.kid,
      publicKey: savedKeys.publicKey,
      privateKey: savedKeys.privateKey,
      publicJWK: savedKeys.publicJWK,
    });

    console.log('\n');
    process.exit(0);
  } catch (error: any) {
    console.error('\n❌ Demo failed:', error.message);
    if (error.cause) {
      console.error('   Cause:', error.cause);
    }
    process.exit(1);
  }
}

void main();
