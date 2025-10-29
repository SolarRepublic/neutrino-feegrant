import type {NaiveHexMixed} from '@blake.regalia/belt';
import type {TrustedContextUrl, WeakUintStr} from '@solar-republic/types';

declare global {
	namespace NodeJS {
		interface ProcessEnv {
			METRICS_AUTH_PASSWORD?: string;
			FEEGRANT_SECRET_KEY_HEX: NaiveHexMixed;
			SECRET_LCD: TrustedContextUrl;
			SECRET_LCD_REQUEST_ORIGIN_HEADER?: string | undefined;
			SECRET_RPC: TrustedContextUrl;
			GAS_PRICE: WeakUintStr;
			ALLOWANCE_AMOUNT: WeakUintStr;
			FEEGRANT_MEMO?: string;
			FEEGRANT_BLOCKS_TIMEOUT?: WeakUintStr;
			FEEGRANT_GAS_LIMIT_GRANT?: WeakUintStr;
			FEEGRANT_GAS_LIMIT_REVOKE?: WeakUintStr;
			SERVER_HOST?: string;
			SERVER_PORT?: WeakUintStr;
			CHAIN_ID?: string;
		}
	}
}
