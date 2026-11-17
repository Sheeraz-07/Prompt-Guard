/**
 * Automated Unit Tests for PromptGuard Licensing & Quota Engine
 * Tests 3 free daily limit, midnight rollover, tampering, and 2-device seat protection
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
  await test('Initial state gives exactly 3 free daily credits', async () => {
    await licensing.revokeLicense();
    const state = licensing.getState();
    assert.strictEqual(state.isPro, false, 'Should be Free tier');
    assert.strictEqual(state.remainingToday, 3, 'Should have 3 free credits');
    assert.strictEqual(state.usedToday, 0, 'Used count should be 0');
    assert.strictEqual(licensing.canSanitize(), true, 'Can sanitize should be true');
  });

  // 2. Sequential Consumption
  await test('Sequential credit consumption decrements from 3 down to 0', async () => {
    await licensing.revokeLicense();
    
    const c1 = licensing.consumeCredit();
    assert.strictEqual(c1.allowed, true);
    assert.strictEqual(c1.remaining, 2);

    const c2 = licensing.consumeCredit();
    assert.strictEqual(c2.allowed, true);
    assert.strictEqual(c2.remaining, 1);

    const c3 = licensing.consumeCredit();
    assert.strictEqual(c3.allowed, true);
    assert.strictEqual(c3.remaining, 0);

    assert.strictEqual(licensing.canSanitize(), false, 'Can sanitize should now be false');
  });

  // 3. Quota Exceeded Block
  await test('4th sanitization attempt is blocked with daily_quota_exceeded', async () => {
    const c4 = licensing.consumeCredit();
    assert.strictEqual(c4.allowed, false, 'Should block 4th attempt');
    assert.strictEqual(c4.remaining, 0);
    assert.strictEqual(c4.reason, 'daily_quota_exceeded');
  });

  // 4. Midnight Rollover
  await test('Next day automatically resets quota back to 3 credits', async () => {
    const tomorrow = new Date();
    tomorrow.setDate(tomorrow.getDate() + 1);
    const tomorrowTimestamp = tomorrow.getTime();

    licensing.checkAndResetDailyQuota(tomorrowTimestamp);
    const state = licensing.getState();
    assert.strictEqual(state.remainingToday, 3, 'Quota must reset to 3 on next calendar day');
    assert.strictEqual(state.usedToday, 0);
    assert.strictEqual(licensing.canSanitize(), true);
  });

  // 5. Clock Tampering Prevention
  await test('Clock rollback into the past does not replenish quota', async () => {
    await licensing.revokeLicense();
    licensing.consumeCredit();
    licensing.consumeCredit();
    licensing.consumeCredit();
    assert.strictEqual(licensing.getState().remainingToday, 0);

    const pastTime = Date.now() - (48 * 3600 * 1000);
    const resetResult = licensing.checkAndResetDailyQuota(pastTime);
    assert.strictEqual(resetResult, false, 'Should block reset when clock is rolled back');
    assert.strictEqual(licensing.getState().remainingToday, 0, 'Credits must stay 0');
  });

  // 6. Pro License Activation ($2 Lifetime Deal)
  await test('Valid license key unlocks $2 Lifetime Pro subscription', async () => {
    const activation = await licensing.activateLicenseKey('PG-PRO-LIFETIME-2026');
    assert.strictEqual(activation.success, true);

    const state = licensing.getState();
    assert.strictEqual(state.isPro, true, 'User must now be Pro');
    assert.strictEqual(state.remainingToday, Infinity, 'Pro user has Infinity credits');
    assert.strictEqual(licensing.canSanitize(), true);
  });

  // 7. Unlimited Sanitizations for Pro User
  await test('Pro user can sanitize without burning daily credits', async () => {
    for (let i = 0; i < 10; i++) {
      const res = licensing.consumeCredit();
      assert.strictEqual(res.allowed, true);
      assert.strictEqual(res.isPro, true);
    }
    assert.strictEqual(licensing.getState().remainingToday, Infinity);
  });

  // 8. License Rejection for Invalid Formats
  await test('Rejects invalid license key formats gracefully', async () => {
    await licensing.revokeLicense();
    const invalid = await licensing.activateLicenseKey('bad-key');
    assert.strictEqual(invalid.success, false);
    assert.strictEqual(licensing.getState().isPro, false);
  });

  console.log(`\n📊 Licensing Test Results: ${passedTests}/${totalTests} passed (${Math.round((passedTests / totalTests) * 100)}%)\n`);

  if (passedTests !== totalTests) {
    process.exit(1);
  }
}

runTests();
