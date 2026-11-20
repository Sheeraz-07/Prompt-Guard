# Contributing to PromptGuard

Thanks for helping make PromptGuard safer and more useful.

## Before opening an issue

- Search existing issues first.
- Never include real credentials, customer data, private URLs, or confidential logs.
- Include the browser version, operating system, reproduction steps, and the smallest safe sample that demonstrates the problem.

## Pull requests

1. Create a focused branch from `main`.
2. Keep detector changes small and add a regression test for each new pattern.
3. Run `npm test`.
4. Explain privacy or permission implications in the pull request description.

Please preserve the local-first behavior: new features should not send prompt content or mappings to an external service.
