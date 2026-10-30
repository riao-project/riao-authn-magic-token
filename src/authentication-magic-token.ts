import { Authentication, Principal } from '@riao/iam';
import {
	AuthenticationOptions,
	AuthenticationRejectedError,
} from '@riao/iam/authentication';
import { Jwt, JwtOptions, Token, isTokenValidationError } from '@riao/crypto';
import {
	defaultTokenOptions,
	MagicTokenPayload,
	MagicTokenRecord,
	TokenOptions,
} from './magic-token';
import { QueryRepository } from '@riao/dbal';
import { KeyValExpression } from '@riao/dbal/expression/key-val-expression';
import { randomUUID } from 'crypto';

export interface MagicTokenAuthenticationOptions extends AuthenticationOptions {
	jwtOptions: JwtOptions;
}

export class MagicTokenAuthentication<
	TPrincipal extends Principal = Principal,
> extends Authentication<TPrincipal> {
	protected jwt: Jwt<MagicTokenPayload & { [key: string]: unknown }>;
	protected magicTokenRepo: QueryRepository<MagicTokenRecord>;

	public constructor(options: MagicTokenAuthenticationOptions) {
		super(options);
		this.jwt = new Jwt(options.jwtOptions);
		this.magicTokenRepo = options.db.getQueryRepository<MagicTokenRecord>({
			table: 'iam_magic_tokens',
			identifiedBy: 'id',
		});
	}

	public async createMagicToken(
		credentials: { login: string },
		options: Partial<TokenOptions> = {}
	): Promise<Token> {
		options = {
			...defaultTokenOptions,
			...options,
		} as TokenOptions;

		const principal = await this.findActivePrincipal({
			where: <KeyValExpression<TPrincipal>>{
				login: credentials.login,
			},
		});

		if (principal === null) {
			throw new AuthenticationRejectedError(
				'Principal not found or not active.'
			);
		}

		const principalId = principal.id;

		// Generate token
		const token = await this.jwt.generateToken(
			{
				type: options.type!,
				principalId: principal.id,
			},
			{
				expiresIn: options.expiresIn,
			}
		);

		await this.magicTokenRepo.insertOne({
			record: {
				principal_id: principalId,
				token: token.token,
				type: options.type,
			},
		});

		return token;
	}

	public async authenticate(credentials: {
		token: string;
		type: string;
	}): Promise<TPrincipal | null> {
		// Never use a bearer secret as a protection subject or metadata.
		const attempt = { scheme: 'magic-token', subject: 'magic-token' };
		const protection = await this.beforeAuthenticationAttempt(attempt);
		if (!protection.allowed) {
			return null;
		}

		let data: MagicTokenPayload;
		try {
			data = await this.jwt.decodeToken(credentials.token);
		}
		catch (error) {
			if (!isTokenValidationError(error)) {
				throw error;
			}
			await this.recordAuthenticationFailure(attempt);
			return null;
		}

		if (
			data.type !== credentials.type ||
			(typeof data.principalId !== 'string' &&
				typeof data.principalId !== 'number')
		) {
			await this.recordAuthenticationFailure(attempt);
			return null;
		}

		const principal = await this.findActivePrincipal({
			where: <KeyValExpression<TPrincipal>>{
				id: data.principalId,
			},
		});

		if (!principal) {
			await this.recordAuthenticationFailure(attempt);
			return null;
		}

		// A conditional write and unique receipt identify the winning attempt.
		const consumptionId = randomUUID();
		await this.magicTokenRepo.update({
			set: { consumption_id: consumptionId },
			where: {
				principal_id: data.principalId,
				token: credentials.token,
				type: credentials.type,
				consumption_id: null,
			},
		});
		const tokenRecord = await this.magicTokenRepo.findOne({
			where: { consumption_id: consumptionId },
		});

		if (!tokenRecord) {
			await this.recordAuthenticationFailure(attempt);
			return null;
		}
		await this.magicTokenRepo.delete({
			where: { consumption_id: consumptionId },
		});

		await this.recordAuthenticationSuccess(attempt);
		return principal;
	}
}
