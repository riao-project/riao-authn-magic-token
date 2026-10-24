# @riao/authn-magic-token

A passwordless authentication driver for the RIAO IAM framework that uses JWT magic tokens for user authentication.

## Overview

Magic-token driver for @riao/iam - magic tokens allow users to log in via a unique, time-limited token sent to their email or other contact method. This is a passwordless authentication approach that improves security by eliminating password-related vulnerabilities.

**Key Features:**
- Passwordless authentication using magic tokens
- Time-limited JWT tokens with configurable expiration
- Tokens are deleted after successful authentication
- Built on RIAO IAM framework
- TypeScript support with full type safety
- PostgreSQL database support

## Installation

```bash
npm install @riao/authn-magic-token @riao/iam @riao/dbal
npm install --save-dev @riao/cli
```

## Quick Start

### 1. Import Migrations

First, ensure you have a database configured and run the migrations:

```bash
npx riao migration:create import-authn-magic-token-tables
```

`database/main/migrations/123456789-import-authn-magic-token-tables.ts`
```typescript
import { AuthenticationMagicTokenMigrations } from '@riao/authn-magic-token';

export default AuthenticationMagicTokenMigrations;
```

Then run the migrations:
```bash
npx riao migration:run
```

### 2. Initialize Authentication

```typescript
import { MagicTokenAuthentication } from '@riao/authn-magic-token';
import { KeyPairGenerator } from '@riao/crypto';
import { Principal } from '@riao/iam';

// Generate keypair for JWT signing
const keypair = new KeyPairGenerator({ algorithm: 'ES512' }).generate();

// Create authentication instance
const auth = new (class extends MagicTokenAuthentication<Principal> {})({
  db,
  jwtOptions: {
    publicKey: keypair.publicKey,
    privateKey: keypair.privateKey,
    algorithm: 'ES512',
  },
});
```

### 3. Create a User

```typescript
const user = await auth.createPrincipal({
  login: 'user@example.com',
  type: 'user',
  name: 'John Doe',
});
```

### 4. Generate Magic Token

```typescript
const magicToken = await auth.createMagicToken(
  { login: 'user@example.com' },
  {
    type: 'auth',
    expiresIn: '10m', // Token expires in 10 minutes
  }
);

console.log('Magic token:', magicToken.token);
// Send this token to the user (e.g., via email)
```

### 5. Authenticate with Magic Token

```typescript
// User clicks link/enters token
const authenticated = await auth.authenticate({
  token: magicToken.token,
  type: 'auth',
});

if (authenticated === null) {
  // Return a generic login rejection (including blocked attempts).
} else {
  // Create your application's session for authenticated.id here.
  // Token has been consumed; do not use it as a session bearer token.
}
```

## Version 3 Authentication Contract

Requires `@riao/iam` 5 and `@riao/crypto` 1.2. Options extend IAM's
`AuthenticationOptions`, including `authenticationProtection`. Authentication
runs `beforeAttempt`, then exactly one `onFailure` for invalid credentials or
`onSuccess` for an authenticated active principal. A denied `beforeAttempt`
returns `null` without recording another failure or success.

`authenticate()` returns a principal or `null` for invalid/expired JWTs,
tokens whose requested type does not match, missing/consumed tokens, inactive
principals, and blocked attempts. Database, signing-key/crypto, and protection-hook operational errors
propagate; do not translate them into bad-credential attempts. JWT rejection
uses crypto's `isTokenValidationError`, not a blanket exception catch.

The coordinated dependency lock entries omit registry `resolved`/`integrity`
until IAM 5 and crypto 1.2 are published. Regenerate with
`npm install --package-lock-only` after release to record registry integrity.

The protection subject is `magic-token` for all hooks (never the secret token
or unverified JWT claims), providing scheme-wide protection.
Applications needing per-client admission limits should enforce those at the
HTTP boundary. Token issuance is a separate API: `createMagicToken()` throws
IAM's `AuthenticationRejectedError` for unknown/inactive principals.

Inactive-principal attempts do not consume tokens. Successful authentication
deletes the matching token record, but concurrent attempts are not atomically
serialized. The token is a credential, **not** a session bearer token: issue an
application-owned session only after a non-null principal is returned.

At an HTTP boundary, use generic rejection responses for `null` and handle
operational errors separately (for example, HTTP 503). `null` deliberately
does not expose a retry delay; APIs that throw IAM's `AuthenticationBlockedError`
can expose its optional `retryAfterSeconds` as `Retry-After` with HTTP 429.
Never disclose account existence or log bearer credentials.

## Token Expiration

Tokens are time-limited using the `expiresIn` option. Common values:

- `'5m'` - 5 minutes (default)
- `'10m'` - 10 minutes
- `'30m'` - 30 minutes
- `'1h'` - 1 hour
- `'24h'` - 24 hours
- `'7d'` - 7 days

The time format uses the `ms` package notation.

## Best Practices

1. **Send tokens via secure channels** - Always send magic tokens via email, SMS, or other secure channels, not in logs
2. **Set appropriate expiration** - Use shorter expiration times for sensitive operations
3. **Token cleanup** - Successfully authenticated token records are deleted; concurrent attempts are not atomically serialized
4. **Rate limiting** - Consider implementing rate limiting on token creation to prevent abuse
5. **Logging** - Log authentication events for security auditing

## Security Considerations

- Magic tokens are JWT tokens signed with your private key
- Tokens are stored in the database and deleted after use
- Always use HTTPS when transmitting tokens
- Keep your private keys secure
- Consider adding CAPTCHA or rate limiting for token generation

## Extending the Class

You can extend `MagicTokenAuthentication` to customize behavior:

```typescript
class CustomMagicTokenAuth extends MagicTokenAuthentication<CustomPrincipal> {
  public async createMagicToken(credentials, options = {}) {
    // Custom logic here
    const token = await super.createMagicToken(credentials, options);

    return token;
  }
}
```

## Contributing & Development

See [contributing.md](docs/contributing/contributing.md) for information on how to develop or contribute to this project!

## License

See [LICENSE.md](LICENSE.md) for details.

## Dependencies

- `@riao/dbal` - Database abstraction layer
- `@riao/iam` - IAM framework and JWT utilities
