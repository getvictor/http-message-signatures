#!/usr/bin/env node
/**
 * Demo script: Client enrollment
 * Generates keys and registers with the server
 */

import { runEnrollmentDemo } from './demo-client.js';
import { saveKeys, keysExist } from './key-storage.js';

async function main() {
  try {
    // Check if already enrolled
    if (keysExist()) {
      console.log('\n⚠️  Client is already enrolled!');
      console.log('   Keys found in .demo-keys/client-keys.json');
      console.log('\n   To re-enroll:');
      console.log('   1. Delete the .demo-keys directory');
      console.log('   2. Run this script again\n');
      process.exit(0);
    }

    // Run enrollment
    const { clientId, keys } = await runEnrollmentDemo();

    // Save keys for future demos
    await saveKeys(clientId, keys.kid, keys.publicKey, keys.privateKey);

    console.log('\n🎉 Ready for demos!');
    console.log('   Run: npm run demo:good');
    console.log('   Run: npm run demo:bad-method\n');

    process.exit(0);
  } catch (error: any) {
    console.error('\n❌ Enrollment failed:', error.message);
    if (error.cause) {
      console.error('   Cause:', error.cause);
    }
    process.exit(1);
  }
}

void main();
