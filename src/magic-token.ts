import { DatabaseRecordId } from '@riao/dbal';
import ms from 'ms';

export interface TokenOptions {
	type: string;
	expiresIn: ms.StringValue;
}

export const defaultTokenOptions: TokenOptions = {
	type: 'auth',
	expiresIn: '5m',
};

export interface MagicTokenPayload {
	type: string;
	principalId: DatabaseRecordId;
}

export interface MagicTokenRecord {
	id: DatabaseRecordId;
	principal_id: DatabaseRecordId;
	created_at: Date;
	type: string;
	token: string;
}
