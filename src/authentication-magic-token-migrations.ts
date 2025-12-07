import { Migration } from '@riao/dbal';
import { AuthMigrations } from '@riao/iam/auth/auth-migrations';
// eslint-disable-next-line max-len
import { CreateMagicTokenTable } from './migrations/001-create-magic-token-table';

export class AuthenticationMagicTokenMigrations extends AuthMigrations {
	override package = '@riao/authn-magic-token';
	override name = '@riao/authn-magic-token';

	override async getMigrations(): Promise<
		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		Record<string, typeof Migration<any>>
		> {
		return {
			...(await super.getMigrations()),
			'create-magic-token-table': CreateMagicTokenTable,
		};
	}
}
