# @riao/authn-magic-token

A passwordless authentication driver for the RIAO IAM framework that uses magic tokens (one-time use JWT tokens) for user authentication.

## Overview

Magic-token driver for @riao/iam - magic tokens allow users to log in via a unique, time-limited token sent to their email or other contact method. This is a passwordless authentication approach that improves security by eliminating password-related vulnerabilities.

**Key Features:**
- Passwordless authentication using magic tokens
- Time-limited JWT tokens with configurable expiration
- One-time token usage (tokens are deleted after successful authentication)
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
import { KeyPairGenerator, Principal } from '@riao/iam';

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

console.log('Authenticated user:', authenticated);
// Token is automatically deleted after successful authentication
```

## Database Schema

The authentication system creates a `iam_magic_tokens` table with the following structure:

```sql
CREATE TABLE iam_magic_tokens (
  id SERIAL PRIMARY KEY,
  principal_id INTEGER NOT NULL REFERENCES iam_principals(id),
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  type VARCHAR(255) NOT NULL,
  token TEXT NOT NULL
);
```

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
3. **One-time use** - Tokens are automatically deleted after successful authentication
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
