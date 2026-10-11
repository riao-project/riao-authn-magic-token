import { Migration, MigrationPackage } from '@riao/dbal';
// eslint-disable-next-line max-len
import { CreateMagicTokenTable } from './migrations/001-create-magic-token-table';
import {
	AddTokenConsumptionId,
} from './migrations/002-add-token-consumption-id';

export class AuthenticationMagicTokenMigrations extends MigrationPackage {
	override package = '@riao/authn-magic-token';
	override name = '@riao/authn-magic-token';

	override async getMigrations(): Promise<
		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		Record<string, typeof Migration<any>>
		> {
		return {
			'create-magic-token-table': CreateMagicTokenTable,
			'add-token-consumption-id': AddTokenConsumptionId,
		};
	}
}
