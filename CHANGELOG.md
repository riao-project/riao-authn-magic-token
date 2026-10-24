# authn-magic-token - Changelog
# 3.0.0

- Require IAM 5 and crypto 1.2; accept authentication protection options.
- Return `null` for expected authentication rejection, including blocked and
  inactive-principal attempts; propagate operational errors.
- Token issuance uses IAM's typed expected rejection; authenticated principals
  must be exchanged for application-owned sessions, not magic bearer sessions.
