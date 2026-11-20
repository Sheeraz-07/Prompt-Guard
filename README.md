# PromptGuard

![PromptGuard](icons/icon128.png)

**PromptGuard is a free, local-first Chrome extension that sanitizes secrets and personal data before you paste code, logs, configuration, or prompts into an AI tool.**

[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Chrome Manifest V3](https://img.shields.io/badge/Chrome-Manifest%20V3-4285F4.svg)](manifest.json)
[![No network requests](https://img.shields.io/badge/privacy-no%20network%20requests-16a34a.svg)](#privacy)

PromptGuard helps developers use ChatGPT, Claude, Gemini, Copilot, and other AI assistants without accidentally sharing credentials or sensitive data. It runs in the browser, keeps the original-to-placeholder mapping in the current session, and supports reversible sanitization.

## Why PromptGuard?

AI assistants are useful for debugging, code review, and incident response, but pasted input can contain credentials, tokens, customer data, or internal connection strings. PromptGuard adds a local safety step:

1. Paste text or grab selected text from the active Chrome tab.
2. Detect secrets and PII locally.
3. Mask, permanently strip, or replace matches with synthetic demo values.
4. Restore masked values locally when you need the original response context.

## Features

- **Free and unlimited**: no account, quota, payment, or cloud service.
- **Local-first privacy**: sanitization happens in the extension; no input is sent to PromptGuard servers.
- **Reversible masking** with placeholders such as `[OPENAI_API_KEY_1]`.
- **Permanent strip mode** for sharing sanitized text without a restoration map.
- **Synthetic mock mode** for realistic, non-secret test values.
- **One-click active-tab capture** for selected text.
- **Session vault** for the current browser session, with a shred control.
- **Custom regex rules** for organization-specific tokens.
- **Category filters** for AI providers, cloud, version control, cryptography, databases, auth, communication, payments, PII, and generic secrets.

Detectors include common OpenAI, Anthropic, Gemini, GitHub, AWS, Azure, Slack, JWT, private-key, database URI, webhook, password-assignment, email, phone, SSN, credit-card, and IBAN patterns. Pattern matching is heuristic: always review sanitized output before sharing.

## Install in Chrome

1. Download or clone this repository.
2. Open `chrome://extensions`.
3. Enable **Developer mode**.
4. Click **Load unpacked** and select the repository folder.
5. Click the PromptGuard toolbar icon to open the side panel.

The extension targets Chromium browsers that support Manifest V3 side panels.

## Usage

- **Mask & Replace** keeps a mapping so placeholders can be restored.
- **Total Strip** replaces matches with `[REDACTED]` and is not intended for restoration.
- **Synthetic Mock** substitutes safe dummy values for demos and tests.
- Use **Rules** to disable categories or add a custom regular expression.
- Use **Restore** to replace placeholders in an AI response using the active session mapping.

## Development

No build step or external dependency is required.

```bash
npm test
```

The test suite covers the sanitizer engine, duplicate handling, restoration, format detection, custom rules, PII, cloud credentials, and the free-access compatibility API.

## Privacy

PromptGuard is designed to work without a backend. The sanitizer and UI are bundled in the extension, and the extension manifest does not request host-wide browsing access. The active-tab capture feature only reads selected text after you invoke it. Do not treat regex detection as a guarantee of safe disclosure; inspect the final text before sending it to any third-party AI service.

## Contributing

Bug reports, detector improvements, documentation fixes, and browser compatibility patches are welcome. Read [CONTRIBUTING.md](CONTRIBUTING.md) before opening a pull request.

## Security

Please report suspected vulnerabilities privately according to [SECURITY.md](SECURITY.md). Do not publish real credentials in issues, pull requests, fixtures, or screenshots.

## License

PromptGuard is released under the [MIT License](LICENSE).
