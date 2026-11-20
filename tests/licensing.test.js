/**
 * Automated Unit Tests for PromptGuard's free access compatibility API
 * Run with: node tests/licensing.test.js
 */

const assert = require('assert');
const licensing = require('../utils/licensing.js');

let totalTests = 0;
let passedTests = 0;

async function test(description, fn) {
  totalTests++;
  try {
    await fn();
    passedTests++;
    console.log(`  ✓ ${description}`);
  } catch (err) {
    console.error(`  ✗ FAIL: ${description}`);
    console.error(`    ${err.message}`);
  }
}

async function runTests() {
  console.log('\n💳 Running PromptGuard Licensing & Quota Tests...\n');

  // 1. Initial State
  await test('Initial state is free and unlimited', async () => {
    await licensing.revokeLicense();
    const state = licensing.getState();
    assert.strictEqual(state.isPro, true, 'Should be unlimited');
    assert.strictEqual(state.remainingToday, Infinity, 'Should have unlimited credits');
    assert.strictEqual(state.usedToday, 0, 'Used count should be 0');
    assert.strictEqual(licensing.canSanitize(), true, 'Can sanitize should be true');
  });

  // 2. Sequential Consumption
  await test('Sanitization remains available after repeated consumption', async () => {
    await licensing.revokeLicense();
    
    for (let i = 0; i < 10; i++) {
      const result = licensing.consumeCredit();
      assert.strictEqual(result.allowed, true);
      assert.strictEqual(result.remaining, Infinity);
    }
    assert.strictEqual(licensing.canSanitize(), true, 'Sanitization must remain available');
  });

  // 3. Midnight rollover remains harmless
  await test('Date rollover keeps access unlimited', async () => {
    const tomorrow = new Date();
    tomorrow.setDate(tomorrow.getDate() + 1);
    const tomorrowTimestamp = tomorrow.getTime();

    licensing.checkAndResetDailyQuota(tomorrowTimestamp);
    const state = licensing.getState();
    assert.strictEqual(state.remainingToday, Infinity);
    assert.strictEqual(licensing.canSanitize(), true);
  });

  // 4. Compatibility activation
  await test('Legacy activation calls remain harmless', async () => {
    const activation = await licensing.activateLicenseKey('legacy-key');
    assert.strictEqual(activation.success, true);

    const state = licensing.getState();
    assert.strictEqual(state.isPro, true);
    assert.strictEqual(state.remainingToday, Infinity);
    assert.strictEqual(licensing.canSanitize(), true);
  });

  console.log(`\n📊 Licensing Test Results: ${passedTests}/${totalTests} passed (${Math.round((passedTests / totalTests) * 100)}%)\n`);

  if (passedTests !== totalTests) {
    process.exit(1);
  }
}

runTests();
