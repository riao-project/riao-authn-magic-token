# authn-magic-token - Changelog

## Unreleased

- Atomically claim magic tokens before returning a principal to prevent
  concurrent replay; add the nullable token-consumption receipt migration.
- Preserve existing authentication interfaces and errors.
