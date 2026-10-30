import { Database, SelectQuery, UpdateOptions } from '@riao/dbal';
import { Jwt } from '@riao/crypto';
import { Principal } from '@riao/iam';
import {
	AuthenticationProtection,
	AuthenticationRejectedError,
} from '@riao/iam/authentication';
import { MagicTokenAuthentication } from '../../src';
import { MagicTokenRecord } from '../../src/magic-token';

describe('Magic token authentication contract', () => {
	let auth: MagicTokenAuthentication;
	let principalRepo: jasmine.SpyObj<{
		findOne: () => Promise<object | null>;
	}>;
	let tokens: jasmine.SpyObj<{
		update: (options: UpdateOptions<MagicTokenRecord>) => Promise<void>;
		findOne: (options: SelectQuery<MagicTokenRecord>) =>
			Promise<MagicTokenRecord | null>;
		delete: (options: SelectQuery<MagicTokenRecord>) => Promise<void>;
	}>;
	let protection: jasmine.SpyObj<AuthenticationProtection>;
	const jwt = new Jwt({ secret: 'test-secret', algorithm: 'HS512' });
	let token: string;
	const principal: Principal = {
		id: '7', login: 'user@example.com', type: 'user', name: 'User',
		create_timestamp: new Date(),
	};

	beforeEach(async () => {
		principalRepo = jasmine.createSpyObj('principalRepo', ['findOne']);
		principalRepo.findOne.and.resolveTo(principal);
		tokens = jasmine.createSpyObj('tokens', [
			'update', 'findOne', 'delete',
		]);
		tokens.update.and.resolveTo();
		tokens.delete.and.resolveTo();
		protection = jasmine.createSpyObj('protection', [
			'beforeAttempt', 'onFailure', 'onSuccess',
		]);
		protection.beforeAttempt.and.resolveTo({ allowed: true });
		protection.onFailure.and.resolveTo();
		protection.onSuccess.and.resolveTo();
		const db = {
			getQueryRepository: jasmine.createSpy().and.returnValues(
				principalRepo, tokens
			),
		} as unknown as Database;
		auth = new MagicTokenAuthentication({
			db, authenticationProtection: protection,
			jwtOptions: { secret: 'test-secret', algorithm: 'HS512' },
		});
		token = (await jwt.generateToken({
			type: 'auth', principalId: 7,
		})).token;
		tokens.findOne.and.resolveTo({
			id: 1, principal_id: 7, type: 'auth', token,
			consumption_id: null, created_at: new Date(),
		});
	});

	it('runs before and success hooks, and never exposes the token to hooks',
		async () => {
			expect(await auth.authenticate({ token, type: 'auth' }))
				.toEqual(principal);
			expect(protection.beforeAttempt).toHaveBeenCalledTimes(1);
			expect(protection.onSuccess).toHaveBeenCalledTimes(1);
			expect(protection.onFailure).not.toHaveBeenCalled();
			expect(JSON.stringify(protection.beforeAttempt.calls.allArgs()))
				.not.toContain(token);
			const claim = tokens.update.calls.mostRecent().args[0];
			const claimWhere = claim.where as Partial<MagicTokenRecord>;
			const receipt = claim.set.consumption_id as string;
			const lookupWhere = tokens.findOne.calls.mostRecent().args[0]
				.where as Partial<MagicTokenRecord>;
			const deleteWhere = tokens.delete.calls.mostRecent().args[0]
				.where as Partial<MagicTokenRecord>;
			expect(claimWhere.principal_id).toBe(7);
			expect(claimWhere.token).toBe(token);
			expect(claimWhere.type).toBe('auth');
			expect(claimWhere.consumption_id).toBeNull();
			expect(typeof receipt).toBe('string');
			expect(lookupWhere.consumption_id).toBe(receipt);
			expect(deleteWhere.consumption_id).toBe(receipt);
		});

	it('returns null when blocked without counting a failure', async () => {
		protection.beforeAttempt.and.resolveTo({
			allowed: false, retryAfterSeconds: 30,
		});
		expect(await auth.authenticate({ token, type: 'auth' })).toBeNull();
		expect(principalRepo.findOne).not.toHaveBeenCalled();
		expect(tokens.update).not.toHaveBeenCalled();
		expect(protection.onFailure).not.toHaveBeenCalled();
		expect(protection.onSuccess).not.toHaveBeenCalled();
	});

	it('counts a requested token type mismatch as a failure', async () => {
		expect(await auth.authenticate({ token, type: 'reset' })).toBeNull();
		expect(protection.onFailure).toHaveBeenCalledTimes(1);
		expect(tokens.update).not.toHaveBeenCalled();
	});

	it('counts malformed and expired JWTs as failures', async () => {
		const expired = await jwt.generateToken(
			{ type: 'auth', principalId: 7 }, { expiresIn: -1 }
		);
		for (const invalid of ['invalid', expired.token]) {
			expect(await auth.authenticate({
				token: invalid, type: 'auth',
			})).toBeNull();
		}
		expect(protection.onFailure).toHaveBeenCalledTimes(2);
		expect(tokens.update).not.toHaveBeenCalled();
	});

	it('rejects inactive principals without consuming the token', async () => {
		principalRepo.findOne.and.resolveTo(null);
		expect(await auth.authenticate({ token, type: 'auth' })).toBeNull();
		expect(tokens.findOne).not.toHaveBeenCalled();
		expect(protection.onFailure).toHaveBeenCalledTimes(1);
		expect(protection.onSuccess).not.toHaveBeenCalled();
	});

	it('counts missing tokens as authentication failures', async () => {
		tokens.findOne.and.resolveTo(null);
		expect(await auth.authenticate({
			token, type: 'auth',
		})).toBeNull();
		expect(protection.onFailure).toHaveBeenCalledTimes(1);
		expect(protection.onSuccess).not.toHaveBeenCalled();
	});

	it('propagates token deletion errors without counting failure',
		async () => {
			const outage = new Error('cleanup unavailable');
			tokens.delete.and.rejectWith(outage);
			await expectAsync(auth.authenticate({
				token, type: 'auth',
			}))
				.toBeRejectedWith(outage);
			expect(tokens.update).toHaveBeenCalledTimes(1);
			expect(tokens.findOne).toHaveBeenCalledTimes(1);
			expect(protection.onFailure).not.toHaveBeenCalled();
			expect(protection.onSuccess).not.toHaveBeenCalled();
		});

	it('propagates database and protection outages without counting failure',
		async () => {
			const outage = new Error('database unavailable');
			tokens.update.and.rejectWith(outage);
			await expectAsync(auth.authenticate({ token, type: 'auth' }))
				.toBeRejectedWith(outage);
			expect(protection.onFailure).not.toHaveBeenCalled();
			expect(protection.onSuccess).not.toHaveBeenCalled();
			protection.beforeAttempt.and.rejectWith(outage);
			await expectAsync(auth.authenticate({ token, type: 'auth' }))
				.toBeRejectedWith(outage);
			expect(protection.onFailure).not.toHaveBeenCalled();
		});

	it('does not swallow unexpected JWT decoder errors', async () => {
		const outage = new Error('crypto unavailable');
		spyOn(auth['jwt'], 'decodeToken').and.rejectWith(outage);
		await expectAsync(auth.authenticate({ token, type: 'auth' }))
			.toBeRejectedWith(outage);
		expect(protection.onFailure).not.toHaveBeenCalled();
	});

	it('propagates success-hook outages without counting failed credentials',
		async () => {
			const outage = new Error('protection unavailable');
			protection.onSuccess.and.rejectWith(outage);
			await expectAsync(auth.authenticate({ token, type: 'auth' }))
				.toBeRejectedWith(outage);
			expect(protection.onFailure).not.toHaveBeenCalled();
		});

	it('deletes the claimed token before recording success', async () => {
		protection.onSuccess.and.callFake(async () => {
			expect(tokens.delete).toHaveBeenCalledTimes(1);
		});
		expect(await auth.authenticate({ token, type: 'auth' }))
			.toEqual(principal);
		expect(protection.onSuccess).toHaveBeenCalledTimes(1);
	});

	it('uses typed rejection for token issuance to unknown principals',
		async () => {
			principalRepo.findOne.and.resolveTo(null);
			await expectAsync(auth.createMagicToken({ login: 'unknown' }))
				.toBeRejectedWithError(AuthenticationRejectedError);
		});
});
