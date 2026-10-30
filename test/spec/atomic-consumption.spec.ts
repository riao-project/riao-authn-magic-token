import 'jasmine';
import { Database, UpdateOptions, SelectQuery } from '@riao/dbal';
import { Jwt } from '@riao/crypto';
import { Principal } from '@riao/iam';
import { MagicTokenAuthentication } from '../../src/authentication-magic-token';
import { MagicTokenRecord } from '../../src/magic-token';

describe('Atomic magic token consumption', () => {
	const principal: Principal = {
		id: '7', login: 'user@example.com', type: 'user', name: 'User',
		create_timestamp: new Date(),
	};
	let auth: MagicTokenAuthentication;
	let token: string;
	let row: MagicTokenRecord | null;
	let tokens: jasmine.SpyObj<{
		update: (options: UpdateOptions<MagicTokenRecord>) => Promise<void>;
		findOne: (options: SelectQuery<MagicTokenRecord>) =>
			Promise<MagicTokenRecord | null>;
		delete: (options: SelectQuery<MagicTokenRecord>) => Promise<void>;
	}>;

	beforeEach(async () => {
		token = (await new Jwt({
			secret: 'test-secret', algorithm: 'HS512',
		}).generateToken({ type: 'auth', principalId: principal.id })).token;
		row = {
			id: 'token-id', principal_id: principal.id, type: 'auth',
			token, consumption_id: null, created_at: new Date(),
		};
		tokens = jasmine.createSpyObj('tokens', [
			'update', 'findOne', 'delete',
		]);
		tokens.update.and.callFake(async (options) => {
			const where = options.where as Partial<MagicTokenRecord>;
			if (
				row && row.principal_id === where.principal_id &&
				row.token === where.token && row.type === where.type &&
				row.consumption_id === where.consumption_id
			) {
				Object.assign(row, options.set);
			}
		});
		tokens.findOne.and.callFake(async (options) => {
			const where = options.where as Partial<MagicTokenRecord>;
			return row && row.consumption_id === where.consumption_id ?
				{ ...row } : null;
		});
		tokens.delete.and.callFake(async (options) => {
			const where = options.where as Partial<MagicTokenRecord>;
			if (row?.consumption_id === where.consumption_id) {
				row = null;
			}
		});
		const principals = jasmine.createSpyObj('principals', ['findOne']);
		principals.findOne.and.resolveTo(principal);
		const db = {
			getQueryRepository: jasmine.createSpy().and.returnValues(
				principals, tokens
			),
		} as unknown as Database;
		auth = new MagicTokenAuthentication({
			db, jwtOptions: { secret: 'test-secret', algorithm: 'HS512' },
		});
	});

	const authenticate = async () => auth.authenticate({ token, type: 'auth' });

	it('allows exactly one concurrent attempt and rejects subsequent replay',
		async () => {
			const results = await Promise.allSettled([
				authenticate(), authenticate(),
			]);
			expect(results.filter((r) => r.status === 'fulfilled').length)
				.toBe(2);
			expect(results.filter((r) =>
				r.status === 'fulfilled' && r.value === principal
			).length).toBe(1);
			expect(results.filter((r) =>
				r.status === 'fulfilled' && r.value === null
			).length).toBe(1);
			expect(tokens.update).toHaveBeenCalledTimes(2);
			const receipts = tokens.update.calls.allArgs().map(
				([options]) => String(options.set.consumption_id)
			);
			expect(receipts[0]).not.toEqual(receipts[1]);
			expect(tokens.delete).toHaveBeenCalledTimes(1);
			expect(row).toBeNull();
			expect(await authenticate()).toBeNull();
		});

	it('matches the token, principal, type, and unused receipt in the claim',
		async () => {
			await authenticate();
			const where = tokens.update.calls.mostRecent().args[0]
				.where as Partial<MagicTokenRecord>;
			expect(where).toEqual({
				principal_id: principal.id, token, type: 'auth',
				consumption_id: null,
			});
			const deleted = tokens.delete.calls.mostRecent().args[0]
				.where as Partial<MagicTokenRecord>;
			expect(deleted).toEqual({
				consumption_id: jasmine.any(String),
			});
		});

	it('cannot claim a token belonging to a different principal', async () => {
		row!.principal_id = 'other';
		expect(await authenticate()).toBeNull();
		expect(tokens.delete).not.toHaveBeenCalled();
	});

	it('rejects claimed tokens after cleanup fails', async () => {
		tokens.delete.and.rejectWith(new Error('cleanup failed'));
		await expectAsync(authenticate())
			.toBeRejectedWithError('cleanup failed');
		expect(row!.consumption_id).toEqual(jasmine.any(String));
		expect(await authenticate()).toBeNull();
		expect(tokens.delete).toHaveBeenCalledTimes(1);
	});

	it('counts a wrong-type token as a failure without consuming it',
		async () => {
			expect(await auth.authenticate({
				token, type: 'other',
			})).toBeNull();
			expect(tokens.update).not.toHaveBeenCalled();
		});

	it('propagates claim database failures without cleanup', async () => {
		tokens.update.and.rejectWith(new Error('database unavailable'));
		await expectAsync(authenticate())
			.toBeRejectedWithError('database unavailable');
		expect(tokens.findOne).not.toHaveBeenCalled();
		expect(tokens.delete).not.toHaveBeenCalled();
	});
});
