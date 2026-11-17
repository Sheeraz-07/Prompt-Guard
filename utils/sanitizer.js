/**
 * PromptGuard: AI PII & Secret Sanitizer
 * utils/sanitizer.js - Core Regex & Masking Engine
 * 100% Client-side. Zero external network requests.
 */

(function (root, factory) {
  if (typeof define === 'function' && define.amd) {
    define([], factory);
  } else if (typeof module === 'object' && module.exports) {
    module.exports = factory();
  } else {
    root.PromptGuardSanitizer = factory();
  }
})(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  // Rule definitions with priority, category, regex, and placeholder prefix
  const RULE_DEFINITIONS = [
    // 1. Cryptographic Private Keys (High Priority - multiline blocks)
    {
      id: 'private_key',
      name: 'Private Key Block',
      category: 'crypto',
      prefix: 'PRIVATE_KEY',
      regex: /-----BEGIN (?:RSA |DSA |EC |OPENSSH |PGP )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |DSA |EC |OPENSSH |PGP )?PRIVATE KEY-----/g,
      mock: () => '-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0mockKeyVal...DEMO...NOT_A_REAL_KEY==\n-----END RSA PRIVATE KEY-----'
    },

    // 2. Database Connection Strings (with embedded passwords)
    {
      id: 'database_uri',
      name: 'Database Connection URI',
      category: 'database',
      prefix: 'DATABASE_URL',
      regex: /\b(?:postgres|postgresql|mysql|mongodb|mongodb\+srv|redis|rediss|amqp|amqps|mssql):\/\/(?:[a-zA-Z0-9_\-\.%]+:[^@\s"'`]+@)[a-zA-Z0-9_.\-]+(?::\d+)?(?:\/[a-zA-Z0-9_\-\.%]+)?(?:\?[a-zA-Z0-9_.\-=%&]*)?/gi,
      mock: () => 'postgres://mock_user:mock_password@localhost:5432/mock_db'
    },

    // 3. Azure Connection Strings
    {
      id: 'azure_connection_string',
      name: 'Azure Connection String',
      category: 'cloud',
      prefix: 'AZURE_CONNECTION_STRING',
      regex: /\bDefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[^;]+;[^\s"']+/gi,
      mock: () => 'DefaultEndpointsProtocol=https;AccountName=mockstorage;AccountKey=ZXhhbXBsZWtleTEyMzQ1Njc4OTA==;EndpointSuffix=core.windows.net'
    },

    // 4. JWT Tokens
    {
      id: 'jwt_token',
      name: 'JSON Web Token (JWT)',
      category: 'auth',
      prefix: 'JWT_TOKEN',
      regex: /\beyJ[a-zA-Z0-9_\-]{8,}\.eyJ[a-zA-Z0-9_\-]{8,}\.[a-zA-Z0-9_\-]{10,}\b/g,
      mock: () => 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6Ik1vY2sgVXNlciIsImlhdCI6MTUxNjIzOTAyMn0.mockSignatureString1234567890abcdef'
    },

    // 5. AI Providers
    {
      id: 'openai_project_key',
      name: 'OpenAI Project API Key',
      category: 'ai',
      prefix: 'OPENAI_API_KEY',
      regex: /\bsk-(?:proj|admin)-[a-zA-Z0-9_\-]{20,100}\b/g,
      mock: () => 'sk-proj-mockDemoKeyOpenAI892348912309482348923489'
    },
    {
      id: 'openai_legacy_key',
      name: 'OpenAI API Key (Standard)',
      category: 'ai',
      prefix: 'OPENAI_API_KEY',
      regex: /\bsk-[a-zA-Z0-9]{20,60}\b/g,
      mock: () => 'sk-mockStandardKeyOpenAI09128390128301298310'
    },
    {
      id: 'anthropic_key',
      name: 'Anthropic Claude API Key',
      category: 'ai',
      prefix: 'ANTHROPIC_API_KEY',
      regex: /\bsk-ant-[a-zA-Z0-9_\-]{32,100}\b/g,
      mock: () => 'sk-ant-api03-mockAnthropicKeyDemo982347109283741029384710293847'
    },
    {
      id: 'google_gemini_key',
      name: 'Google Gemini / GCP API Key',
      category: 'ai',
      prefix: 'GEMINI_API_KEY',
      regex: /\bAIza[0-9A-Za-z\-_]{30,40}\b/g,
      mock: () => 'AIzaSyMockDemoGoogleApiKey1234567890'
    },
    {
      id: 'huggingface_token',
      name: 'HuggingFace Access Token',
      category: 'ai',
      prefix: 'HUGGINGFACE_TOKEN',
      regex: /\bhf_[a-zA-Z0-9]{34,40}\b/g,
      mock: () => 'hf_mockHuggingFaceTokenDemo1234567890'
    },
    {
      id: 'replicate_token',
      name: 'Replicate API Token',
      category: 'ai',
      prefix: 'REPLICATE_API_TOKEN',
      regex: /\br8_[a-zA-Z0-9]{32,45}\b/g,
      mock: () => 'r8_mockReplicateTokenDemo1234567890abcdef'
    },
    {
      id: 'perplexity_key',
      name: 'Perplexity API Key',
      category: 'ai',
      prefix: 'PERPLEXITY_API_KEY',
      regex: /\bpplx-[a-zA-Z0-9]{48,56}\b/g,
      mock: () => 'pplx-mockDemoPerplexityApiKey123456789012345678901234'
    },
    {
      id: 'groq_key',
      name: 'Groq API Key',
      category: 'ai',
      prefix: 'GROQ_API_KEY',
      regex: /\bgsk_[a-zA-Z0-9]{52}\b/g,
      mock: () => 'gsk_mockGroqApiKeyDemo12345678901234567890123456789012'
    },

    // 6. Cloud Infrastructure
    {
      id: 'aws_access_key',
      name: 'AWS Access Key ID',
      category: 'cloud',
      prefix: 'AWS_ACCESS_KEY',
      regex: /\b(?:AKIA|ASIA|AROA|AIPA)[0-9A-Z]{16}\b/g,
      mock: () => 'AKIAIOSFODNN7EXAMPLE'
    },
    {
      id: 'digitalocean_token',
      name: 'DigitalOcean Personal Access Token',
      category: 'cloud',
      prefix: 'DO_ACCESS_TOKEN',
      regex: /\bdop_v1_[a-f0-9]{64}\b/g,
      mock: () => 'dop_v1_0000000000000000000000000000000000000000000000000000000000000000'
    },

    // 7. Developer & VCS Platforms
    {
      id: 'github_pat_fine',
      name: 'GitHub Fine-grained PAT',
      category: 'vcs',
      prefix: 'GITHUB_PAT',
      regex: /\bgithub_pat_[a-zA-Z0-9_]{30,100}\b/g,
      mock: () => 'github_pat_11AAAAAAA01234567890AB_cdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNOPQRSTUVW'
    },
    {
      id: 'github_pat_classic',
      name: 'GitHub Classic Token',
      category: 'vcs',
      prefix: 'GITHUB_TOKEN',
      regex: /\bgh[pousr]_[a-zA-Z0-9]{36}\b/g,
      mock: () => 'ghp_mockGitHubPersonalAccessToken12345678'
    },
    {
      id: 'gitlab_pat',
      name: 'GitLab Personal Access Token',
      category: 'vcs',
      prefix: 'GITLAB_TOKEN',
      regex: /\bglpat-[a-zA-Z0-9\-=_]{20,26}\b/g,
      mock: () => 'glpat-mockGitLabPatDemo12345'
    },
    {
      id: 'npm_token',
      name: 'NPM Access Token',
      category: 'vcs',
      prefix: 'NPM_TOKEN',
      regex: /\bnpm_[a-zA-Z0-9]{36}\b/g,
      mock: () => 'npm_mockNpmAccessTokenDemo1234567890'
    },
    {
      id: 'pypi_token',
      name: 'PyPI Upload Token',
      category: 'vcs',
      prefix: 'PYPI_TOKEN',
      regex: /\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_\-]{50,}\b/g,
      mock: () => 'pypi-AgEIcHlwaS5vcmcCJG1vY2stZGVtby10b2tlbi1weXBpLTEyMzQ1Njc4OTAABCDE'
    },
    {
      id: 'docker_pat',
      name: 'Docker Hub PAT',
      category: 'vcs',
      prefix: 'DOCKER_PAT',
      regex: /\bdckr_pat_[a-zA-Z0-9_\-]{27}\b/g,
      mock: () => 'dckr_pat_mockDockerHubPatDemo123'
    },

    // 8. Communication Services
    {
      id: 'slack_token',
      name: 'Slack OAuth / Bot Token',
      category: 'communication',
      prefix: 'SLACK_TOKEN',
      regex: /\bxox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}\b/g,
      mock: () => 'xoxb-123456789012-123456789012-mockSlackBotTokenDemo1234'
    },
    {
      id: 'slack_webhook',
      name: 'Slack Incoming Webhook',
      category: 'communication',
      prefix: 'SLACK_WEBHOOK_URL',
      regex: /https:\/\/hooks\.slack\.com\/services\/T[a-zA-Z0-9_]+\/B[a-zA-Z0-9_]+\/[a-zA-Z0-9_]+/g,
      mock: () => 'https://hooks.slack.com/services/T00000000/B00000000/mockSlackWebhookToken1234'
    },
    {
      id: 'discord_webhook',
      name: 'Discord Webhook URL',
      category: 'communication',
      prefix: 'DISCORD_WEBHOOK_URL',
      regex: /https:\/\/(?:ptb\.|canary\.)?discord(?:app)?\.com\/api\/webhooks\/\d{17,20}\/[A-Za-z0-9_\-]+/g,
      mock: () => 'https://discord.com/api/webhooks/123456789012345678/mockDiscordWebhookSecretToken123456789'
    },
    {
      id: 'telegram_bot_token',
      name: 'Telegram Bot Token',
      category: 'communication',
      prefix: 'TELEGRAM_BOT_TOKEN',
      regex: /\b\d{8,10}:[a-zA-Z0-9_\-]{35}\b/g,
      mock: () => '123456789:mockTelegramBotTokenSecretKey12345'
    },

    // 9. Fintech & Payments
    {
      id: 'stripe_secret_key',
      name: 'Stripe Secret / Restricted Key',
      category: 'payment',
      prefix: 'STRIPE_SECRET_KEY',
      regex: /\b(?:sk|rk)_(?:live|test)_[0-9a-zA-Z]{24,34}\b/g,
      mock: () => 'sk_live_mockDemoStripeSecretKey123456'
    },
    {
      id: 'square_access_token',
      name: 'Square Access Token',
      category: 'payment',
      prefix: 'SQUARE_TOKEN',
      regex: /\b(?:sq0csp-[0-9A-Za-z\-_]{43}|sq0atp-[0-9A-Za-z\-_]{22})\b/g,
      mock: () => 'sq0csp-mockSquareAccessTokenDemoKey1234567890123'
    },
    {
      id: 'credit_card',
      name: 'Credit Card Number',
      category: 'payment',
      prefix: 'CREDIT_CARD',
      regex: /\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12})\b/g,
      mock: () => '4532-0123-4567-8910'
    },
    {
      id: 'iban',
      name: 'International Bank Account (IBAN)',
      category: 'payment',
      prefix: 'IBAN_NUMBER',
      regex: /\b[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7}(?:[A-Z0-9]?){0,16}\b/g,
      mock: () => 'GB29NWBK60161331926819'
    },

    // 10. Personally Identifiable Information (PII)
    {
      id: 'email',
      name: 'Email Address',
      category: 'pii',
      prefix: 'EMAIL',
      regex: /\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b/g,
      mock: (counter) => `user_${counter}@example.com`
    },
    {
      id: 'us_ssn',
      name: 'US Social Security Number (SSN)',
      category: 'pii',
      prefix: 'US_SSN',
      regex: /\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b/g,
      mock: () => '000-12-3456'
    },
    {
      id: 'phone',
      name: 'Phone Number',
      category: 'pii',
      prefix: 'PHONE',
      regex: /(?:\+?(\d{1,3}))?[-.\s]?(?:\(?(\d{2,4})\)?[-.\s]?)?(\d{3,4})[-.\s]?(\d{3,4})\b/g,
      validate: (match) => {
        // Exclude short numbers or non-phones (must have 7 to 15 digits)
        const digits = match.replace(/\D/g, '');
        return digits.length >= 7 && digits.length <= 15;
      },
      mock: () => '+1 (555) 019-2834'
    },
    {
      id: 'ipv4_address',
      name: 'IPv4 Address',
      category: 'network',
      prefix: 'IP_ADDRESS',
      regex: /\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/g,
      validate: (match) => {
        // Optionally preserve standard localhost/loopback
        return match !== '127.0.0.1' && match !== '0.0.0.0';
      },
      mock: () => '192.0.2.1'
    },
    {
      id: 'mac_address',
      name: 'MAC Address',
      category: 'network',
      prefix: 'MAC_ADDRESS',
      regex: /\b(?:[0-9A-Fa-f]{2}[:-]){5}(?:[0-9A-Fa-f]{2})\b/g,
      mock: () => '00:1A:2B:3C:4D:5E'
    },

    // 11. Authorization Headers
    {
      id: 'auth_header',
      name: 'Authorization Bearer Header',
      category: 'auth',
      prefix: 'AUTH_BEARER',
      regex: /(?:Authorization\s*:\s*Bearer\s+|Bearer\s+)([a-zA-Z0-9_\-\.\+\/=]{20,})/gi,
      valueGroup: 1,
      mock: () => 'Bearer mock_bearer_token_value_abcdef123456'
    }
  ];

  // Generic key-value assignment regex (matches .env, json, yaml, code: KEY="val" or key: 'val')
  const GENERIC_KEY_VALUE_REGEX = /(?:^|[,\s;{])((?:["']?[a-zA-Z0-9_]*(?:secret|password|passwd|api[_-]?key|token|auth|credential|access[_-]?key|private[_-]?key)[a-zA-Z0-9_]*["']?\s*[:=]\s*["']?))([^"'\s\n\r,;}]+)(["']?)/gim;

  /**
   * Helper to detect input type format heuristically
   */
  function detectInputFormat(text) {
    if (!text || typeof text !== 'string') return 'plain';
    const trimmed = text.trim();
    if (trimmed.startsWith('{') && trimmed.endsWith('}')) {
      try {
        JSON.parse(trimmed);
        return 'json';
      } catch (e) {
        /* not pure json */
      }
    }
    if (trimmed.startsWith('curl ')) return 'curl';
    if (/^[A-Z0-9_]+\s*=\s*.+/m.test(trimmed)) return '.env';
    if (/(?:Traceback \(most recent call last\):|Error:|\s+at\s+.+\(?.+:\d+:\d+\)?)/m.test(trimmed)) {
      return 'stacktrace';
    }
    if (/(?:function\s|const\s|let\s|var\s|def\s|class\s|import\s|public\s+class)/m.test(trimmed)) {
      return 'code';
    }
    return 'plain';
  }

  /**
   * Sanitizes text according to chosen mode.
   * 
   * @param {string} text - Raw input string (code, logs, env, etc.)
   * @param {Object} [options]
   * @param {string} [options.mode='mask'] - 'mask' | 'strip' | 'mock'
   * @param {Array<string>} [options.enabledCategories] - Filter categories to scan
   * @param {Array<Object>} [options.customRules] - Optional custom regex rules
   * @returns {Object} { sanitizedText, mapping, stats, threatBreakdown }
   */
  function sanitizeText(text, options = {}) {
    if (typeof text !== 'string') {
      return {
        sanitizedText: '',
        mapping: {},
        stats: { totalThreats: 0, uniqueSecrets: 0 },
        threatBreakdown: {}
      };
    }

    const mode = options.mode || 'mask';
    const enabledCategories = options.enabledCategories || null;
    const customRules = options.customRules || [];

    // Combine standard rules with custom user-defined rules
    const rules = [...RULE_DEFINITIONS];
    if (Array.isArray(customRules)) {
      customRules.forEach((cr, idx) => {
        if (cr && cr.pattern) {
          try {
            rules.unshift({
              id: `custom_${idx}`,
              name: cr.name || `Custom Rule ${idx + 1}`,
              category: 'custom',
              prefix: (cr.prefix || 'CUSTOM_SECRET').toUpperCase().replace(/[^A-Z0-9_]/g, '_'),
              regex: new RegExp(cr.pattern, cr.flags || 'g'),
              mock: () => 'MOCK_CUSTOM_VALUE'
            });
          } catch (e) {
            console.warn('Invalid custom regex:', cr.pattern, e);
          }
        }
      });
    }

    // Step 1: Find all matches across rules while preventing overlapping spans
    const detectedMatches = [];
    const occupiedSpans = [];

    function isSpanOccupied(start, end) {
      for (const span of occupiedSpans) {
        if (start < span.end && end > span.start) {
          return true;
        }
      }
      return false;
    }

    // 1. Run structured & token patterns
    for (const rule of rules) {
      if (enabledCategories && !enabledCategories.includes(rule.category)) {
        continue;
      }

      const regex = new RegExp(rule.regex.source, rule.regex.flags);
      let match;

      while ((match = regex.exec(text)) !== null) {
        let rawSecret = match[0];
        let matchStart = match.index;
        let matchEnd = match.index + rawSecret.length;

        // If rule specifies a capture group for the actual secret value
        if (rule.valueGroup && match[rule.valueGroup]) {
          const prefixPart = match[0].substring(0, match[0].indexOf(match[rule.valueGroup]));
          matchStart = match.index + prefixPart.length;
          rawSecret = match[rule.valueGroup];
          matchEnd = matchStart + rawSecret.length;
        }

        // Validate match if validator function exists
        if (rule.validate && !rule.validate(rawSecret, match)) {
          continue;
        }

        // Prevent overlapping replacements
        if (!isSpanOccupied(matchStart, matchEnd)) {
          occupiedSpans.push({ start: matchStart, end: matchEnd });
          detectedMatches.push({
            rule,
            rawSecret,
            start: matchStart,
            end: matchEnd
          });
        }
      }
    }

    // 2. Run Generic Key-Value Assignment Pattern
    if (!enabledCategories || enabledCategories.includes('generic') || enabledCategories.includes('auth')) {
      const genericRegex = new RegExp(GENERIC_KEY_VALUE_REGEX.source, GENERIC_KEY_VALUE_REGEX.flags);
      let genMatch;

      while ((genMatch = genericRegex.exec(text)) !== null) {
        // genMatch[1] = key & assignment, genMatch[2] = value, genMatch[3] = closing quote
        const fullMatch = genMatch[0];
        const keyPart = genMatch[1];
        const secretVal = genMatch[2];
        const valStart = genMatch.index + (fullMatch.indexOf(keyPart) + keyPart.length);
        const valEnd = valStart + secretVal.length;

        // Skip if empty or already masked
        if (!secretVal || secretVal.trim().length === 0 || secretVal.startsWith('[') && secretVal.endsWith(']')) {
          continue;
        }

        if (!isSpanOccupied(valStart, valEnd)) {
          occupiedSpans.push({ start: valStart, end: valEnd });
          detectedMatches.push({
            rule: {
              id: 'generic_secret',
              name: 'Secret / Password Assignment',
              category: 'generic',
              prefix: 'SECRET_VALUE',
              mock: () => 'mock_secret_password_xyz'
            },
            rawSecret: secretVal,
            start: valStart,
            end: valEnd
          });
        }
      }
    }

    // Step 2: Sort matches by start position in text
    detectedMatches.sort((a, b) => a.start - b.start);

    // Step 3: Build mapping and replacement values
    // Map same rawSecret to identical placeholder tag to preserve semantics
    const secretToPlaceholder = new Map();
    const placeholderToSecret = {};
    const prefixCounters = {};
    const threatBreakdown = {};

    let totalThreats = detectedMatches.length;

    detectedMatches.forEach((item) => {
      const { rule, rawSecret } = item;
      const prefix = rule.prefix;

      // Update threat breakdown stats
      threatBreakdown[rule.name] = (threatBreakdown[rule.name] || 0) + 1;

      if (!secretToPlaceholder.has(rawSecret)) {
        prefixCounters[prefix] = (prefixCounters[prefix] || 0) + 1;
        const placeholder = `[${prefix}_${prefixCounters[prefix]}]`;
        secretToPlaceholder.set(rawSecret, placeholder);
        placeholderToSecret[placeholder] = rawSecret;
      }

      item.placeholder = secretToPlaceholder.get(rawSecret);

      if (mode === 'mock') {
        item.replacement = typeof rule.mock === 'function' ? rule.mock(prefixCounters[prefix]) : '[MOCK_VALUE]';
      } else if (mode === 'strip') {
        item.replacement = '[REDACTED]';
      } else {
        item.replacement = item.placeholder;
      }
    });

    // Step 4: Perform string replacements from end to start (preserves indices)
    let sanitizedText = text;
    for (let i = detectedMatches.length - 1; i >= 0; i--) {
      const match = detectedMatches[i];
      sanitizedText =
        sanitizedText.substring(0, match.start) +
        match.replacement +
        sanitizedText.substring(match.end);
    }

    return {
      sanitizedText,
      mapping: placeholderToSecret,
      stats: {
        totalThreats,
        uniqueSecrets: Object.keys(placeholderToSecret).length
      },
      threatBreakdown,
      detectedMatches: detectedMatches.map(m => ({
        ruleName: m.rule.name,
        category: m.rule.category,
        placeholder: m.placeholder,
        maskedPreview: maskSecretPreview(m.rawSecret)
      }))
    };
  }

  /**
   * Restores sanitized text back to original values using the mapping dictionary.
   * 
   * @param {string} sanitizedText - Text containing [PLACEHOLDER] tokens
   * @param {Object} mapping - Dictionary of { '[PLACEHOLDER]': 'realSecret' }
   * @returns {Object} { restoredText, restoredCount, unmappedPlaceholders }
   */
  function restoreText(sanitizedText, mapping) {
    if (typeof sanitizedText !== 'string') {
      return { restoredText: '', restoredCount: 0, unmappedPlaceholders: [] };
    }

    if (!mapping || typeof mapping !== 'object' || Object.keys(mapping).length === 0) {
      return { restoredText: sanitizedText, restoredCount: 0, unmappedPlaceholders: [] };
    }

    let restoredText = sanitizedText;
    let restoredCount = 0;
    const unmappedPlaceholders = [];

    // Find all placeholder-like tokens [PREFIX_NUM] in text
    const placeholderRegex = /\[([A-Z0-9_]+_\d+)\]/g;
    const foundTokens = new Set();
    let tokenMatch;

    while ((tokenMatch = placeholderRegex.exec(sanitizedText)) !== null) {
      foundTokens.add(tokenMatch[0]);
    }

    // Replace known placeholders
    for (const [placeholder, originalSecret] of Object.entries(mapping)) {
      if (placeholder && originalSecret) {
        // Escape brackets for regex
        const escaped = placeholder.replace(/[-\/\\^$*+?.()|[\]{}]/g, '\\$&');
        const count = (restoredText.match(new RegExp(escaped, 'g')) || []).length;
        if (count > 0) {
          restoredText = restoredText.replace(new RegExp(escaped, 'g'), originalSecret);
          restoredCount += count;
        }
      }
    }

    // Check for any tokens remaining in the text that were not in the mapping
    foundTokens.forEach((token) => {
      if (!mapping[token]) {
        unmappedPlaceholders.push(token);
      }
    });

    return {
      restoredText,
      restoredCount,
      unmappedPlaceholders
    };
  }

  /**
   * Safe preview generator: shows first few and last few characters, stars out the rest
   */
  function maskSecretPreview(secret) {
    if (!secret || typeof secret !== 'string') return '';
    if (secret.length <= 8) return '****';
    const start = secret.slice(0, 4);
    const end = secret.slice(-3);
    return `${start}...${end}`;
  }

  return {
    RULE_DEFINITIONS,
    sanitizeText,
    restoreText,
    detectInputFormat,
    maskSecretPreview
  };
});
