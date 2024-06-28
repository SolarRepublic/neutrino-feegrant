import type { NaiveHexMixed } from "@blake.regalia/belt";
import type { TrustedContextUrl, WeakUintStr } from "@solar-republic/types";

declare global {
	namespace NodeJS {
		interface ProcessEnv {
			SERVER_SK: NaiveHexMixed;
			SECRET_LCD: TrustedContextUrl;
			SECRET_RPC: TrustedContextUrl;
			GAS_PRICE: WeakUintStr;
			ALLOWANCE_AMOUNT: WeakUintStr;
			FEEGRANT_MEMO?: string;
			SERVER_HOST?: string;
			SERVER_PORT?: WeakUintStr;
		}
	}
}