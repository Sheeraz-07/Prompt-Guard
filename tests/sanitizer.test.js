/**
 * Automated Unit Test Suite for PromptGuard Sanitizer Engine
 * Run with: node tests/sanitizer.test.js
 */

const assert = require('assert');
const sanitizer = require('../utils/sanitizer.js');

let totalTests = 0;
let passedTests = 0;

function test(description, fn) {
  totalTests++;
  try {
    fn();
    passedTests++;
    console.log(`  ✓ ${description}`);
  } catch (err) {
    console.error(`  ✗ FAIL: ${description}`);
    console.error(`    ${err.message}`);
  }
}

console.log('\n🔒 Running PromptGuard Engine Tests...\n');

// 1. OpenAI Key Detection & Restoration
test('Detects and restores OpenAI Project Key and Standard Key', () => {
  const input = `
    const client = new OpenAI({
      apiKey: "sk-proj-abc12345678901234567890def",
      legacyKey: "sk-abcdef123456789012345678"
    });
  `;
  const result = sanitizer.sanitizeText(input, { mode: 'mask' });
  assert(result.sanitizedText.includes('[OPENAI_API_KEY_1]'), 'Should contain [OPENAI_API_KEY_1]');
  assert(result.sanitizedText.includes('[OPENAI_API_KEY_2]'), 'Should contain [OPENAI_API_KEY_2]');
  assert(!result.sanitizedText.includes('sk-proj-'), 'Real project key must not exist in sanitized text');
  
  // Restoration test
  const restored = sanitizer.restoreText(result.sanitizedText, result.mapping);
  assert.strictEqual(restored.restoredText, input, 'Restored text must match original input exactly');
  assert.strictEqual(restored.restoredCount, 2, 'Should have restored 2 keys');
});

// 2. Duplicate Secret Handling
test('Reuses identical placeholder tag for duplicate secrets', () => {
  const secret = 'sk-proj-sameSecretValueRepeatedTwice12345';
  const input = `First: "${secret}", Second: "${secret}"`;
  const result = sanitizer.sanitizeText(input, { mode: 'mask' });
  
  assert.strictEqual(result.stats.uniqueSecrets, 1, 'Should register only 1 unique secret');
  assert.strictEqual(result.stats.totalThreats, 2, 'Should register 2 total occurrences');
  assert.strictEqual(
    result.sanitizedText,
    'First: "[OPENAI_API_KEY_1]", Second: "[OPENAI_API_KEY_1]"',
    'Both occurrences must have the same placeholder'
  );

  const restored = sanitizer.restoreText(result.sanitizedText, result.mapping);
  assert.strictEqual(restored.restoredText, input, 'Should restore both instances cleanly');
});

// 3. GitHub Tokens & Cloud Providers
test('Detects GitHub PATs and AWS Access Key', () => {
  const input = `
    GITHUB_PAT=github_pat_11AAAAAAA01234567890AB_cdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNOPQRSTUVW
    GH_CLASSIC=ghp_123456789012345678901234567890123456
    AWS_KEY=AKIAIOSFODNN7EXAMPLE
    GCP_KEY=AIzaSyA1234567890123456789012345678901
  `;
  const result = sanitizer.sanitizeText(input, { mode: 'mask' });
  assert(result.sanitizedText.includes('[GITHUB_PAT_1]'));
  assert(result.sanitizedText.includes('[GITHUB_TOKEN_1]'));
  assert(result.sanitizedText.includes('[AWS_ACCESS_KEY_1]'));
  assert(result.sanitizedText.includes('[GEMINI_API_KEY_1]'));

  const restored = sanitizer.restoreText(result.sanitizedText, result.mapping);
  assert.strictEqual(restored.restoredText, input);
});

// 4. Database Connection URI with Passwords
test('Masks Database Connection URI containing credentials', () => {
  const input = 'DATABASE_URL="postgres://admin:SuperSecretPass123!@db.internal.company.com:5432/prod_db?sslmode=require"';
  const result = sanitizer.sanitizeText(input, { mode: 'mask' });
  assert(result.sanitizedText.includes('[DATABASE_URL_1]'), 'Should mask database URL');
  assert(!result.sanitizedText.includes('SuperSecretPass123!'), 'Password must not leak');

  const restored = sanitizer.restoreText(result.sanitizedText, result.mapping);
  assert.strictEqual(restored.restoredText, input);
});

// 5. JWT Token Detection
test('Detects and masks JWT Tokens', () => {
  const jwt = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';
  const input = `Authorization: Bearer ${jwt}`;
  const result = sanitizer.sanitizeText(input, { mode: 'mask' });
  assert(result.sanitizedText.includes('[JWT_TOKEN_1]'), 'Should mask JWT');

  const restored = sanitizer.restoreText(result.sanitizedText, result.mapping);
  assert.strictEqual(restored.restoredText, input);
});

// 6. PII: Emails, Phone Numbers, SSN
test('Masks PII: Email, Phone, and SSN', () => {
  const input = 'Contact alice.smith@enterprise.org or +1 (555) 234-5678, SSN: 123-45-6789';
  const result = sanitizer.sanitizeText(input, { mode: 'mask' });
  assert(result.sanitizedText.includes('[EMAIL_1]'));
  assert(result.sanitizedText.includes('[PHONE_1]'));
  assert(result.sanitizedText.includes('[US_SSN_1]'));

  const restored = sanitizer.restoreText(result.sanitizedText, result.mapping);
  assert.strictEqual(restored.restoredText, input);
});

// 7. Generic .env Password / Secret assignments
test('Detects generic password & secret assignments in .env / config', () => {
  const input = `
    ADMIN_PASSWORD="myVerySecurePassword!99"
    API_SECRET = 'random_secret_hash_value_xyz'
  `;
  const result = sanitizer.sanitizeText(input, { mode: 'mask' });
  assert(result.sanitizedText.includes('[SECRET_VALUE_1]'));
  assert(result.sanitizedText.includes('[SECRET_VALUE_2]'));
  assert(!result.sanitizedText.includes('myVerySecurePassword!99'));

  const restored = sanitizer.restoreText(result.sanitizedText, result.mapping);
  assert.strictEqual(restored.restoredText, input);
});

// 8. Private Key Block Detection
test('Masks entire PEM Private Key Block', () => {
  const input = `
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA0mockKeyVal1234567890abcdefghijklmnopqrstuvwxyz
ABCDEF1234567890==
-----END RSA PRIVATE KEY-----
`;
  const result = sanitizer.sanitizeText(input, { mode: 'mask' });
  assert(result.sanitizedText.includes('[PRIVATE_KEY_1]'));
  assert(!result.sanitizedText.includes('MIIEowIBAAKCAQEA0mockKeyVal1234567890abcdefghijklmnopqrstuvwxyz'));

  const restored = sanitizer.restoreText(result.sanitizedText, result.mapping);
  assert.strictEqual(restored.restoredText, input);
});

// 9. Total Strip Mode
test('Total Strip mode replaces secrets with [REDACTED]', () => {
  const input = 'My token is ghp_123456789012345678901234567890123456 and email test@example.com';
  const result = sanitizer.sanitizeText(input, { mode: 'strip' });
  assert(result.sanitizedText.includes('[REDACTED]'));
  assert(!result.sanitizedText.includes('ghp_'));
  assert(!result.sanitizedText.includes('test@example.com'));
});

// 10. Synthetic Mock Mode
test('Synthetic Mock mode generates realistic dummy values', () => {
  const input = 'OpenAI: sk-proj-12345678901234567890abcdef and email dev@example.com';
  const result = sanitizer.sanitizeText(input, { mode: 'mock' });
  assert(result.sanitizedText.includes('sk-proj-mockDemoKeyOpenAI'));
  assert(result.sanitizedText.includes('user_1@example.com'));
});

// 11. Format Detector
test('Accurately detects input formats (.env, JSON, stacktrace, code, curl)', () => {
  assert.strictEqual(sanitizer.detectInputFormat('{"key": "value"}'), 'json');
  assert.strictEqual(sanitizer.detectInputFormat('PORT=8080\nDB_PASS=xyz'), '.env');
  assert.strictEqual(sanitizer.detectInputFormat('curl -H "Auth: abc" https://api.com'), 'curl');
  assert.strictEqual(sanitizer.detectInputFormat('Traceback (most recent call last):\n  File "app.py", line 12'), 'stacktrace');
  assert.strictEqual(sanitizer.detectInputFormat('const x = () => { return 42; };'), 'code');
});

// 12. Category Filter
test('Filters out disabled categories when specified', () => {
  const input = 'Key: sk-proj-12345678901234567890abcdef, Email: user@test.com';
  // Only enable 'pii', disable 'ai'
  const result = sanitizer.sanitizeText(input, { mode: 'mask', enabledCategories: ['pii'] });
  assert(result.sanitizedText.includes('sk-proj-'), 'AI key should not be masked when AI category disabled');
  assert(result.sanitizedText.includes('[EMAIL_1]'), 'Email should be masked when PII category is enabled');
});

// 13. Custom Regex Rule Support
test('Supports user-defined custom regex rules', () => {
  const input = 'Internal token: ACME-CORP-TOKEN-998877';
  const customRules = [
    {
      name: 'Acme Corp Internal Token',
      prefix: 'ACME_TOKEN',
      pattern: 'ACME-CORP-TOKEN-\\d+',
      flags: 'g'
    }
  ];
  const result = sanitizer.sanitizeText(input, { mode: 'mask', customRules });
  assert(result.sanitizedText.includes('[ACME_TOKEN_1]'), 'Should match custom token');

  const restored = sanitizer.restoreText(result.sanitizedText, result.mapping);
  assert.strictEqual(restored.restoredText, input);
});

// 14. Azure Connection String & Slack Webhooks
test('Detects Azure Connection String and Slack Webhooks', () => {
  const input = `
    AZURE_CONN="DefaultEndpointsProtocol=https;AccountName=prodstorage;AccountKey=ZXhhbXBsZWtleTEyMzQ1Njc4OTA==;EndpointSuffix=core.windows.net"
    SLACK_URL="https://hooks.slack.com/services/T01234567/B01234567/abc123DEF456ghi789JKL012"
    SLACK_BOT="xoxb-123456789012-123456789012-123456789012345678901234"
  `;
  const result = sanitizer.sanitizeText(input, { mode: 'mask' });
  assert(result.sanitizedText.includes('[AZURE_CONNECTION_STRING_1]'));
  assert(result.sanitizedText.includes('[SLACK_WEBHOOK_URL_1]'));
  assert(result.sanitizedText.includes('[SLACK_TOKEN_1]'));

  const restored = sanitizer.restoreText(result.sanitizedText, result.mapping);
  assert.strictEqual(restored.restoredText, input);
});

// 15. Financial Data (Credit Card & IBAN)
test('Detects Credit Card and IBAN', () => {
  const input = 'Pay with card: 4532891023456789, IBAN: GB29NWBK60161331926819';
  const result = sanitizer.sanitizeText(input, { mode: 'mask' });
  assert(result.sanitizedText.includes('[CREDIT_CARD_1]'));
  assert(result.sanitizedText.includes('[IBAN_NUMBER_1]'));

  const restored = sanitizer.restoreText(result.sanitizedText, result.mapping);
  assert.strictEqual(restored.restoredText, input);
});

// 16. Edge Cases: Empty or Malformed Input
test('Handles empty and edge-case inputs gracefully without throwing', () => {
  assert.strictEqual(sanitizer.sanitizeText('').sanitizedText, '');
  assert.strictEqual(sanitizer.sanitizeText(null).sanitizedText, '');
  assert.strictEqual(sanitizer.sanitizeText(undefined).sanitizedText, '');
  assert.strictEqual(sanitizer.restoreText('', {}).restoredText, '');
  assert.strictEqual(sanitizer.restoreText('normal text without tokens', {}).restoredText, 'normal text without tokens');
});

console.log(`\n📊 Test Results: ${passedTests}/${totalTests} passed (${Math.round((passedTests / totalTests) * 100)}%)\n`);

if (passedTests !== totalTests) {
  process.exit(1);
}
