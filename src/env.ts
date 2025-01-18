import type {NaiveHexMixed} from '@blake.regalia/belt';
import type {TrustedContextUrl, WeakUintStr} from '@solar-republic/types';

declare global {
	namespace NodeJS {
		interface ProcessEnv {
			SERVER_SK: NaiveHexMixed;
			SECRET_LCD: TrustedContextUrl;
			SECRET_LCD_REQUEST_ORIGIN_HEADER?: string | undefined;
			SECRET_RPC: TrustedContextUrl;
			GAS_PRICE: WeakUintStr;
			ALLOWANCE_AMOUNT: WeakUintStr;
			FEEGRANT_MEMO?: string;
			FEEGRANT_GAS_LIMIT_GRANT?: WeakUintStr;
			FEEGRANT_GAS_LIMIT_REVOKE?: WeakUintStr;
			SERVER_HOST?: string;
			SERVER_PORT?: WeakUintStr;
			CHAIN_ID?: string;
		}
	}
}
