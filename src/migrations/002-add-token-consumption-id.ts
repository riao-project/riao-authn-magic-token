import { ColumnType, Migration } from '@riao/dbal';

export class AddTokenConsumptionId extends Migration {
	override async up(): Promise<void> {
		await this.ddl.addColumns({
			table: 'iam_magic_tokens',
			columns: [{
				name: 'consumption_id', type: ColumnType.VARCHAR, length: 64,
			}],
		});
	}

	override async down(): Promise<void> {
		await this.ddl.dropColumn({
			table: 'iam_magic_tokens', column: 'consumption_id',
		});
	}
}
