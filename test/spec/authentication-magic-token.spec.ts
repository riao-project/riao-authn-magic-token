import 'jasmine';

import { createDatabase, runMigrations, runMigrationsDown } from '../database';
import { Principal, KeyPairGenerator } from '@riao/iam';
import { Token } from '@riao/iam/jwt';
import { MagicTokenAuthentication } from '../../src/authentication-magic-token';
// eslint-disable-next-line max-len
import { AuthenticationMagicTokenMigrations } from '../../src/authentication-magic-token-migrations';

describe('Authentication - Magic Token', () => {
	const db = createDatabase('authentication-magic-token');

	const keypair = new KeyPairGenerator({ algorithm: 'ES512' }).generate();

	const auth = new (class extends MagicTokenAuthentication<Principal> {})({
		db,
		jwtOptions: {
			publicKey: keypair.publicKey,
			privateKey: keypair.privateKey,
			algorithm: 'ES512',
		},
	});

	beforeAll(async () => {
		await db.init();
		await runMigrations(db, new AuthenticationMagicTokenMigrations());
		await runMigrationsDown(db, new AuthenticationMagicTokenMigrations());
		await runMigrations(db, new AuthenticationMagicTokenMigrations());

		await auth.createPrincipal({
			login: 'auth-passwordless@example.com',
			type: 'user',
			name: 'Auth Passwordless',
		});
	});

	afterAll(async () => {
		await db.disconnect();
	});

	it('can login', async () => {
		const email = 'auth-passwordless@example.com';
		const token = await auth.createMagicToken(
			{
				login: email,
			},
			{
				type: 'auth',
			}
		);

		// Wait a second to avoid not-before-time exception
		await new Promise((a) => setTimeout(a, 1000));

		const authenticated = await auth.authenticate({
			token: token.token,
			type: 'auth',
		});

		expect(authenticated).not.toBeNull();
		expect(authenticated!.login).toEqual(email);
	});

	it('can reject wrong email', async () => {
		const email = 'not_a_user@example.com';
		await expectAsync(
			auth.createMagicToken({ login: email })
		).toBeRejectedWithError('Principal not found or not active.');
	});

	it('can reject wrong token', async () => {
		const email = 'auth-passwordless@example.com';
		const tokenObj: Token = await auth.createMagicToken(
			{ login: email },
			{ type: 'auth' }
		);

		// Simulate a bad token by changing one letter to a 9
		const token: string = tokenObj.token.replace(/[a-z]/, '9');

		// Wait a second to avoid not-before-time exception
		await new Promise((a) => setTimeout(a, 1000));

		await expectAsync(
			auth.authenticate({ token, type: 'auth' })
		).toBeRejected();
	});

	it('can reject expired token', async () => {
		const email = 'auth-passwordless@example.com';
		const tokenObj: Token = await auth.createMagicToken(
			{ login: email },
			{
				type: 'auth',
				expiresIn: '1s',
			}
		);

		// Wait 1+ seconds to expire the token
		await new Promise((a) => setTimeout(a, 1100));
		await expectAsync(
			auth.authenticate({ token: tokenObj.token, type: 'auth' })
		).toBeRejected();
	});

	it('can reject wrong type of token', async () => {
		const email = 'auth-passwordless@example.com';
		const tokenObj: Token = await auth.createMagicToken(
			{ login: email },
			{ type: 'auth' }
		);

		// Wait a second to avoid not-before-time exception
		await new Promise((a) => setTimeout(a, 1000));
		await expectAsync(
			auth.authenticate({ token: tokenObj.token, type: 'wrong-type' })
		).toBeRejectedWithError(
			'Wrong type of token provided for this operation.'
		);
	});

	it('cannot use token twice', async () => {
		const email = 'once@example.com';
		await auth.createPrincipal({
			login: email,
			type: 'user',
			name: 'Once User',
		});

		const tokenObj: Token = await auth.createMagicToken(
			{ login: email },
			{ type: 'auth' }
		);

		// Wait a second to avoid not-before-time exception
		await new Promise((a) => setTimeout(a, 1000));

		await auth.authenticate({ token: tokenObj.token, type: 'auth' });

		await expectAsync(
			auth.authenticate({ token: tokenObj.token, type: 'auth' })
		).toBeRejectedWithError('Token is invalid or expired.');
	});
});
