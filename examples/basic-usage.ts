/* eslint-disable no-console */
import { MagicTokenAuthentication } from '../src/authentication-magic-token';
import { Principal, KeyPairGenerator } from '@riao/iam';
import { createDatabase, runMigrations } from '../test/database';
// eslint-disable-next-line max-len
import { AuthenticationMagicTokenMigrations } from '../src/authentication-magic-token-migrations';
import { AuthMigrations } from '@riao/iam/auth/auth-migrations';
import { maindb } from '../database/main';

/**
 * Basic usage example for Magic Token Authentication
 *
 * This example demonstrates:
 * 1. Setting up a database with magic token tables
 * 2. Creating a MagicTokenAuthentication instance
 * 3. Creating a principal (user)
 * 4. Generating a magic token for login
 * 5. Authenticating using the magic token
 */
async function main() {
	// Step 1: Initialize database
	await maindb.init();
	const db = createDatabase('example-db');
	await db.init();

	// Step 2: Run migrations to create magic token tables
	const migrations = new AuthenticationMagicTokenMigrations();
	await runMigrations(db, new AuthMigrations());
	await runMigrations(db, migrations);

	// Step 3: Generate keypair for JWT signing
	const keypair = new KeyPairGenerator({ algorithm: 'ES512' }).generate();

	// Step 4: Create authentication instance
	const auth = new (class extends MagicTokenAuthentication<Principal> {})({
		db,
		jwtOptions: {
			publicKey: keypair.publicKey,
			privateKey: keypair.privateKey,
			algorithm: 'ES512',
		},
	});

	// Step 5: Create a principal (user)
	const user = await auth.createPrincipal({
		login: 'user@example.com',
		type: 'user',
		name: 'John Doe',
	});

	console.log('✓ Principal created:', user);

	// Step 6: Generate a magic token for login
	const magicToken = await auth.createMagicToken(
		{
			login: 'user@example.com',
		},
		{
			type: 'auth',
			expiresIn: '10m',
		}
	);

	console.log(
		'✓ Magic token generated:',
		magicToken.token.substring(0, 20) + '...'
	);

	// Step 7: Wait a moment (JWT requires time between creation and validation)
	await new Promise((resolve) => setTimeout(resolve, 1000));

	// Step 8: Authenticate using the magic token
	const authenticated = await auth.authenticate({
		token: magicToken.token,
		type: 'auth',
	});

	console.log('✓ Authentication successful:', authenticated);

	// Cleanup
	await db.disconnect();
	console.log('✓ Database disconnected');
	await maindb.disconnect();
	console.log('✓ Main database disconnected');
}

main().catch((error) => {
	console.error('Error:', error.message);
	process.exit(1);
});
