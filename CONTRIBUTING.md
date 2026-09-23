# Contributing to PageDNA

Thanks for helping improve PageDNA, a Manifest V3 Chrome extension for semantic page-integrity monitoring.

## Before you start

- Use Node.js 20 or newer.
- Read the README and the project privacy and trust model before changing collection or storage behavior.
- For security vulnerabilities, do not open a public issue; contact the repository owner privately first.

## Development workflow

1. Create a focused branch from main.
2. Make the smallest change that solves the problem.
3. Run the test suite:

   npm test

4. Run JavaScript syntax checks when changing source files:

   find src tests -name "*.js" -print0 | xargs -0 -n1 node --check

5. For UI or detection changes, load the extension unpacked in Chrome and use the fixture lab where practical.
6. Open a pull request against main with the tests and manual checks clearly described.

## Design and privacy expectations

- Preserve the rule that passwords, cookies, tokens, and form values are never stored.
- Treat page content and scan messages as untrusted input.
- Keep risk evidence explainable and bounded.
- Avoid unrelated formatting or dependency changes.

## Pull requests

Please include:

- A concise explanation of the user-visible or security-relevant change.
- Tests run and their results.
- Manual Chrome verification, or a note explaining why it was not possible.
- Any migration, baseline, permission, or README impact.
