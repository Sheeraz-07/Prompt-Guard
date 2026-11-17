/**
 * PromptGuard: Official License Key Generator Utility
 * Run with: node generate_license_keys.js [count]
 * Example: node generate_license_keys.js 10
 */

const crypto = require('crypto');

function generateKey() {
  const p1 = crypto.randomBytes(2).toString('hex').toUpperCase();
  const p2 = crypto.randomBytes(2).toString('hex').toUpperCase();
  return `PG-PRO-${p1}-${p2}`;
}

const count = parseInt(process.argv[2], 10) || 5;

console.log(`\n🔑 Generating ${count} PromptGuard $2 Lifetime License Keys:\n`);
for (let i = 1; i <= count; i++) {
  console.log(`  ${i}. ${generateKey()}`);
}
console.log(`\n💡 You can provide any of these keys to customers or enter them in the PromptGuard extension to activate Pro Lifetime.\n`);
