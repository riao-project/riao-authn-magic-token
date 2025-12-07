import { Authentication, Principal } from '@riao/iam';
import { AuthOptions } from '@riao/iam/auth/auth';
import { Jwt, JwtOptions, Token } from '@riao/iam/jwt';
import {
	defaultTokenOptions,
	MagicTokenPayload,
	MagicTokenRecord,
	TokenOptions,
} from './magic-token';
import { QueryRepository } from '@riao/dbal';
import { KeyValExpression } from '@riao/dbal/expression/key-val-expression';

export interface MagicTokenAuthenticationOptions extends AuthOptions {
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
			throw new Error('Principal not found or not active.');
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
		// Verify magic token
		const data = await this.jwt.decodeToken(credentials.token);

		if (data.type !== credentials.type) {
			throw new Error('Wrong type of token provided for this operation.');
		}

		// Check principal
		const principal = await this.findActivePrincipal({
			where: <KeyValExpression<TPrincipal>>{
				id: data.principalId,
			},
		});

		// Check token exists
		const tokenRecord = await this.magicTokenRepo.findOne({
			where: {
				principal_id: data.principalId,
				token: credentials.token,
				type: credentials.type,
			},
		});

		if (!tokenRecord) {
			throw new Error('Token is invalid or expired.');
		}

		// Delete token
		await this.magicTokenRepo.delete({
			where: { id: tokenRecord.id },
		});

		return principal;
	}
}
