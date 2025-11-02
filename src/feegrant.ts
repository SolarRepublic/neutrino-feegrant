/* eslint-disable no-console */
import type {SlimAuthInfo, TxResponseTuple} from '@solar-republic/neutrino';
import type {WeakAccountAddr, WeakUintStr, WeakSecretAccAddr, CwUint128} from '@solar-republic/types';

import assert from 'assert';

import {__UNDEFINED, base64_to_text, bytes, bytes_to_text, concat, defer, die, hex_to_bytes, is_error, parse_json_safe, remove, stringify_json, text_to_base64, timeout, timeout_exec, try_async, try_sync} from '@blake.regalia/belt';
import {safe_bytes_to_base64} from '@solar-republic/cosmos-grpc';
import {SI_MESSAGE_TYPE_COSMOS_FEEGRANT_BASIC_ALLOWANCE, anyBasicAllowance, type CosmosFeegrantBasicAllowance} from '@solar-republic/cosmos-grpc/cosmos/feegrant/v1beta1/feegrant';
import {queryCosmosFeegrantAllowance} from '@solar-republic/cosmos-grpc/cosmos/feegrant/v1beta1/query';
import {SI_MESSAGE_TYPE_COSMOS_FEEGRANT_MSG_GRANT_ALLOWANCE, SI_MESSAGE_TYPE_COSMOS_FEEGRANT_MSG_REVOKE_ALLOWANCE, encodeCosmosFeegrantMsgGrantAllowance, encodeCosmosFeegrantMsgRevokeAllowance} from '@solar-republic/cosmos-grpc/cosmos/feegrant/v1beta1/tx';
import {encodeGoogleProtobufAny} from '@solar-republic/cosmos-grpc/google/protobuf/any';

import {bech32_decode} from '@solar-republic/crypto';
import {TendermintEventFilter, TendermintWs, CosmosSigner, auth, broadcast_result, create_and_sign_tx_direct, GC_NEUTRINO} from '@solar-republic/neutrino';
import {IncomingMessage, ServerResponse} from 'http';
import {server} from './server';
import {Counter, Gauge} from 'prom-client';
import {queryCosmosBankBalance} from '@solar-republic/cosmos-grpc/cosmos/bank/v1beta1/query';

type BlockIdFrag = {
	hash: string;
	parts: {
		total: number;
		hash: string;
	};
};


// metrics authorization secret
export const S_METRICS_AUTH_PASSWORD = process.env.METRICS_AUTH_PASSWORD || '';
if(!S_METRICS_AUTH_PASSWORD) {
	console.warn(`Metrics authorization password is not set; metrics will be accessible without authentication`);
}

// metrics authorization
export const SB64_METRICS_AUTH = text_to_base64(`admin:${S_METRICS_AUTH_PASSWORD}`).replace(/=+/, '');

// check feegrant secret key
const SB16_FEERANT_SK = (process.env.FEEGRANT_SECRET_KEY_HEX || '').replace(/^0x/, '');
if(64 !== SB16_FEERANT_SK.length) {
	throw Error(`Invalid feegrant secret key; must be 64 hexadecimal digits. FEEGRANT_SECRET_KEY_HEX is ${SB16_FEERANT_SK? `the wrong length (${SB16_FEERANT_SK.length})`: 'empty'}`);
}

// check LCD
const P_LCD_SECRET = process.env.SECRET_LCD || '';
if(!/^https?:\/\//.test(P_LCD_SECRET)) {
	throw Error(`LCD endpoint must be an HTTP(S) URL`);
}

// check RPC
const P_RPC_SECRET = process.env.SECRET_RPC || '';
if(!/^https?:\/\//.test(P_RPC_SECRET)) {
	throw Error(`RPC endpoint must be an HTTP(S) URL`);
}

// check gas price
const X_GAS_PRICE = parseFloat(process.env.GAS_PRICE);
if(isNaN(X_GAS_PRICE) || !(X_GAS_PRICE > 0)) {
	throw Error(`Invalid gas price setting: ${X_GAS_PRICE}; try setting env var GAS_PRICE=0.1`);
}

// check allowance amount
const XG_ALLOWANCE = BigInt(process.env.ALLOWANCE_AMOUNT);
if(!XG_ALLOWANCE) {
	throw Error(`Invalid allowance amount setting: ${XG_ALLOWANCE}; try setting env var ALLOWANCE_AMOUNT=500000`);
}

// chain ID
const SI_CHAIN_ID = process.env.CHAIN_ID || 'secret-4';

// set optional memo
const S_MEMO = process.env.FEEGRANT_MEMO || '';

// set timeout in number of blocks
const XG_BLOCKS_TIMEOUT = BigInt(process.env.FEEGRANT_BLOCKS_TIMEOUT || 10n);

// gas limits
const XG_LIMIT_GRANT = BigInt(process.env.FEEGRANT_GAS_LIMIT_GRANT || 16_000n);
const XG_LIMIT_REVOKE = BigInt(process.env.FEEGRANT_GAS_LIMIT_REVOKE || 15_000n);

// amount of time to leave for processing before inclusion
const XT_BUFFER_PROCESSING = 1.2e3;

// alpha for EMA
const X_ALPHA_EMA = 0.1;

// create server's feegranter signer
const K_SIGNER = await CosmosSigner(
	hex_to_bytes(SB16_FEERANT_SK),
	SI_CHAIN_ID,
	{
		origin: P_LCD_SECRET,
		headers: {
			origin: process.env.SECRET_LCD_REQUEST_ORIGIN_HEADER || 'starshell.net',
		},
	},
	P_RPC_SECRET,
	[X_GAS_PRICE, 'uscrt'],
	'secret'
);

// open a persistent WebSocket to Secret RPC
const K_TEF_SECRET = await TendermintEventFilter(P_RPC_SECRET);

// number of claims requested
const y_counter_claims_requested = new Counter({
	name: 'feegrant_claims_requested',
	help: 'Number of claims requested',
});

// number of claims already existing
const y_counter_claims_existing = new Counter({
	name: 'feegrant_claims_existing',
	help: 'Number of claims already existing',
});

// number of claims renewed
const y_counter_claims_renewed = new Counter({
	name: 'feegrant_claims_renewed',
	help: 'Number of claims renewed',
});

// number of claims issued
const y_counter_claims_issued = new Counter({
	name: 'feegrant_claims_issued',
	help: 'Number of claims issued',
});

// number of claims enqueued
const y_counter_claims_enqueued = new Counter({
	name: 'feegrant_claims_enqueued',
	help: 'Number of claims enqueued',
});

// number of tx broadcasts succeeded
const y_counter_tx_broadcast_successes = new Counter({
	name: 'feegrant_tx_broadcast_successes',
	help: 'Number of tx broadcasts succeeded',
});

// number of tx broadcasts failed
const y_counter_tx_broadcast_errors = new Counter({
	name: 'feegrant_tx_broadcast_errors',
	help: 'Number of tx broadcasts failed',
});

// block height
const y_gauge_block_height = new Gauge({
	name: 'feegrant_block_height',
	help: 'Current block height',
});

// SCRT balance
const y_gauge_uscrt_balance = new Gauge({
	name: 'feegrant_uscrt_balance',
	help: 'Current balance of the feegrant wallet',
});

// EMA of block time
let xt_ema = 6e3;

// initialize balance
const [g_res_balance] = await queryCosmosBankBalance(K_SIGNER.lcd, K_SIGNER.addr, 'uscrt')
y_gauge_uscrt_balance.set(Number(g_res_balance?.balance?.amount || 0));

// monitor SCRT balance
setTimeout(async function check_balance() {
	// query balance
	const [g_res_balance] = await queryCosmosBankBalance(K_SIGNER.lcd, K_SIGNER.addr, 'uscrt')

	// update gauge
	y_gauge_uscrt_balance.set(Number(g_res_balance?.balance?.amount || 0));

	// schedule next check
	setTimeout(check_balance, xt_ema);
}, xt_ema);

// set websocket timeout
GC_NEUTRINO.WS_TIMEOUT = 1e3

// check interval
let i_regularly_check: NodeJS.Timeout | number = 0;  // eslint-disable-line @typescript-eslint/naming-convention

// regularly check the queue at ideal block time
function check_queue_regularly() {
	// clear any previous intervals
	clearInterval(i_regularly_check);

	// assume block occurs every 6 seconds
	i_regularly_check = setInterval(() => {
		void check_queue();
	}, 6e3);
}

// enqueued message tuple
type Enqueued = [
	atu8_msg: Uint8Array,
	xg_limit: bigint,
	fke_granted: ReturnType<typeof defer>[1],
	sa_grantee: WeakAccountAddr,
];

// enqueued messaged
const a_enqueued: Enqueued[] = [];

// flag controls whether it should wait for account sequence to catch up
let c_clearing = 0;

// termination timeout
let i_terminate: NodeJS.Timeout | number = 0;  // eslint-disable-line @typescript-eslint/naming-convention

// time of the last block
let xt_latest = Date.now();

// subscribe to new blocks and use that as the basis for broadcasts
async function subscribe_new_blocks() {
	// stop regular checks
	clearInterval(i_regularly_check);

	// monitor when new block occurs
	// eslint-disable-next-line @typescript-eslint/naming-convention
	const [[k_ws, e_open]=[], b_timed_out] = await timeout_exec(30e3, () => try_async(() => TendermintWs(P_RPC_SECRET, `tm.event='NewBlock'`, (d_event) => {
		// cancel termination timeout
		clearTimeout(i_terminate);

		// parse message
		const g_data = parse_json_safe<{
			result?: {
				data?: {
					value?: {
						block: {
							header: {
								version: {
									block: `${bigint}`;
								};
								chain_id: string;
								height: `${bigint}`;
								time: string;
								last_block_id: BlockIdFrag;
								last_commit_hash: string;
								data_hash: string;
								validators_hash: string;
								next_validators_hash: string;
								consensus_hash: string;
								app_hash: string;
								last_results_hash: string;
								evidence_hash: string;
								proposer_address: string;
							};

							data: {
								txs: [];
							};

							evidence: {
								evidence: [];
							};

							last_commit: {
								height: `${bigint}`;
								round: number;
								block_id: BlockIdFrag;
								signatures: {
									block_id_flag: number;
									validator_address: string;
									timestamp: string;
									signature: string;
								}[];
							};
						};
						result_begin_block: {};
						result_end_block: {};
					};
				};
			};
		}>(d_event.data);

		// get block height
		const {
			height: sg_height,
			time: sx_time,
		} = g_data?.result?.data?.value?.block?.header || {};

		// update block height
		try_sync(() => y_gauge_block_height.set(Number(sg_height)));

		// get current time
		const xt_now = Date.now();

		// previous measurement exists
		if(xt_latest) {
			// calculate delta
			const xt_delta = xt_now - xt_latest

			// set EMA to initial value
			if(!xt_ema) {
				xt_ema = xt_delta;
			}
			// update EMA
			else {
				xt_ema = (X_ALPHA_EMA * xt_delta) + ((1 - X_ALPHA_EMA) * xt_ema);
			}
		}

		// set latest block time
		xt_latest = xt_now;

		// check the queue right in time for submission
		setTimeout(() => check_queue(sg_height), xt_ema - XT_BUFFER_PROCESSING);

		// set a timeout to terminate the socket if nothing happens
		i_terminate = setTimeout(() => {
			// indicate this executed
			i_terminate = 0;

			// try to kill the socket
			try_sync(() => k_ws?.ws().close());

			// switch to manual interval mode
			check_queue_regularly();
		}, 60e3);
	}, (d_close) => {
		// warn
		console.warn(`WebSocket subscription to new blocks terminated`);

		// cancel the termination timeout for now
		clearTimeout(i_terminate);

		// indicate this is disabled
		i_terminate = 0;

		// a close event was emitted
		if(d_close) console.warn(`Close event received. Type: "${d_close.type}". Reason: "${d_close.reason}".`);

		// warn
		console.warn(`Attempting to recreate WebSocket subscription...`);

		// try to recreate the WebSocket manually
		void subscribe_new_blocks();

		// do not recreate the WebSocket automatically
		return 0;
	})));

	// failed to subscribe in the allotted time
	if(b_timed_out) {
		// switch to manual mode
		check_queue_regularly();

		// try again in a minute
		setTimeout(() => {
			void subscribe_new_blocks();
		}, 60e3);
	}
	// did not time out but failed to connect/open WebSocket
	else if(!k_ws) {
		// warn
		console.warn(`Failed to connect/open WebSocket: ${is_error(e_open)? e_open.stack || e_open.message: e_open+''}`);
		console.warn('Waiting 30s before attempting to recreate WebSocket subscription...');

		// wait
		await timeout(30e3);

		// retry
		void subscribe_new_blocks();
	}
}

// start reacting to new blocks
void subscribe_new_blocks();

// check the queue procedure
async function check_queue(sg_height='X') {
	// clearing
	if(c_clearing > 0) {
		// verbose
		console.log(`Block #${sg_height}; clearing ${c_clearing}`);

		// decrement counter until zero
		c_clearing -= 1;

		// exit
		return;
	}

	// verbose
	console.log(`Block #${sg_height}; ${a_enqueued.length} enqueued, EMA: ${xt_ema}`);

	// process queued messages
	if(a_enqueued.length) {
		// copy enqueued list
		const a_dequeued = a_enqueued.slice();

		// reset length
		a_enqueued.length = 0;

		// prep results
		let a_results: Awaited<ReturnType<typeof broadcast_result>>;

		// auth (default to automatic)
		let z_auth: SlimAuthInfo | 0 = 0;

		// retry-able transaction
		RETRY_TRANSACTION:
		for(let i_retry=0; ; i_retry++) {
			// verbose
			console.log(`Attempt #${i_retry+1}...`);

			// postponed
			const a_postponed: Enqueued[] = [];

			// try processing
			try {
				// should be unique per grantee
				const as_grantees = new Set<string>();

				// remove duplicates
				const as_msgs = new Set<string>();

				// concat all messages
				const a_msgs = a_dequeued.reduce<Uint8Array[]>((a_out, a_queued) => {
					// destructure
					const [atu8_msg,,, sa_grantee] = a_queued;

					// encode message
					const sb64_msg = safe_bytes_to_base64(atu8_msg) || '';

					// not already in set
					if(!as_msgs.has(sb64_msg)) {
						// add to set
						as_msgs.add(sb64_msg);

						// grantee already subject
						if(as_grantees.has(sa_grantee)) {
							// verbose
							console.warn(`Different message exists for same grantee ${sa_grantee}`);

							// remove from dequeued
							remove(a_dequeued, a_queued);

							// postpone queued instruction
							a_postponed.push(a_queued);
						}
						// good to go
						else {
							// add to set
							as_grantees.add(sa_grantee);

							// accept message
							a_out.push(atu8_msg);
						}
					}
					// duplicate
					else {
						// verbose
						console.warn(`Duplicate message found for grantee ${sa_grantee}`);
					}

					// accumulate
					return a_out;
				}, []);

				// compute sum of limits
				const xg_limit = a_dequeued.reduce((xg_sum, [, xg]) => xg_sum + xg, 0n);

				// compute timeout height
				const sg_height_timeout = `${BigInt(sg_height) + XG_BLOCKS_TIMEOUT}` as CwUint128;

				// create and sign tx
				const [atu8_raw, sb16_txn, atu8_signdoc, atu8_signature] = await create_and_sign_tx_direct(K_SIGNER, a_msgs, `${xg_limit}`, __UNDEFINED, z_auth, S_MEMO, __UNDEFINED, __UNDEFINED, sg_height_timeout);

				// log
				console.log(`Broadcasting ${a_msgs.length} messages for ${as_grantees.size} grantees`);
				console.time('broadcast');

				// broadcast
				a_results = await broadcast_result(K_SIGNER, atu8_raw, sb16_txn, K_TEF_SECRET);

				// log
				console.log(`Received broadcast result`);
				console.timeEnd('broadcast');

				// destructure
				const [xc_code, sx_res,, g_meta] = a_results;

				// error
				if(xc_code) {
					// increment error counter
					y_counter_tx_broadcast_errors.inc();

					// verbose
					console.error(`code:${xc_code}; res:${sx_res}; meta:${stringify_json(g_meta)}`);

					// depending on which codespace
					switch(g_meta?.codespace) {
						// SDK codespace
						case 'sdk': {
							// account sequence
							if(32 === g_meta.code) {
								// not yet exceeded retry attempts
								if(i_retry < 2) {
									// verbose
									console.warn(`Retrying failed broadcast on mismatched sequence error`);

									// parse message
									const m_expected = /expected (\d+)/.exec(g_meta.log || '');
									if(m_expected) {
										// fetch auth
										const a_auth = await auth(K_SIGNER);

										// set auth
										z_auth = [a_auth[0], m_expected[1] as WeakUintStr];

										// verbose
										console.warn(`Auth info: ${z_auth[0]}, ${z_auth[1]}`);

										// retry
										continue RETRY_TRANSACTION;
									}
								}
							}
							// something reverted
							else if(38 === g_meta.code) {
								// normalize error message
								const s_error = sx_res || g_meta.log || '';

								// parse message index
								const m_index = /message index: (\d+)/.exec(s_error);
								if(m_index) {
									console.warn(`Failed to parse message index: ${m_index[1]}: ${s_error}`);
								}
							}

							break;
						}

						case __UNDEFINED:
						default: {
							// ignore
						}
					}
				}
				// success
				else {
					// increment counter
					y_counter_tx_broadcast_successes.inc();

					// verbose
					console.log(`✅ ${sb16_txn}: [${a_dequeued.map(([,,, sa_grantee]) => sa_grantee).join(', ')}]`);
				}

				// un-postpone
				a_enqueued.push(...a_postponed);
			}
			// caught error
			catch(e_process) {
				// verbose
				console.warn(`Forwarding failure to callbacks: ${(e_process as Error)?.message || e_process}`);

				// forward error to each callback
				for(const [,, fke_granted] of a_dequeued) {
					fke_granted(__UNDEFINED, e_process as Error);
				}

				// exit
				return;
			}

			// done
			break;
		}

		// each dequeued message
		for(const [,, fke_granted] of a_dequeued) {
			// resolve Promise with transaction result
			fke_granted(a_results);
		}

		// wait for next block to clear account sequence
		c_clearing = 1;
	}
}

// enqueue a message to be signed and broadcasted in next transaction
export async function enqueue(
	atu8_msg: Uint8Array,
	xg_limit: bigint,
	sa_grantee: WeakAccountAddr
): Promise<TxResponseTuple> {
	// create deferred Promise
	const [dp_granted, fke_granted] = defer();

	// increment counter
	y_counter_claims_enqueued.inc();

	// enqueue
	a_enqueued.push([
		atu8_msg,
		xg_limit,
		fke_granted,
		sa_grantee,
	]);

	// return Promise
	return dp_granted;
}


async function claim(
	d_req: IncomingMessage,
	d_res: ServerResponse<IncomingMessage>,
	sa_grantee: WeakSecretAccAddr,
) {
	// increment counter
	y_counter_claims_requested.inc();

	// log request
	console.log(`${d_req.method} ${d_req.url}`);

	// set response headers
	d_res.setHeaders(new Map([
		['access-control-allow-origin', '*'],
		['access-control-allow-methods', 'GET'],
	]));

	// verify address
	try {
		if(!sa_grantee.startsWith('secret1')) die('');
		const atu8_data = bech32_decode(sa_grantee);
		assert(20 === atu8_data.length);
	}
	catch(_e_decode) {
		return (d_res.writeHead(400).write(stringify_json({
			error: 'Invalid bech32 address',
		})), d_res.end());
	}

	// check if user has existing feegrant
	const [g_res_allowance] = await queryCosmosFeegrantAllowance(K_SIGNER.lcd, K_SIGNER.addr, sa_grantee);

	// existing feegrant
	if(g_res_allowance?.allowance) {
		const g_allowance = g_res_allowance.allowance.allowance;

		// increment counter
		y_counter_claims_existing.inc();

		// check allowance type
		if(SI_MESSAGE_TYPE_COSMOS_FEEGRANT_BASIC_ALLOWANCE !== g_allowance?.['@type']) {
			return (d_res.writeHead(500).write(stringify_json({
				error: `Discovered non-basic allowance`,
			})), d_res.end());
		}

		// destructure allowance object
		const {
			spend_limit: a_limits,
			expiration: s_expiration,
		} = g_allowance as CosmosFeegrantBasicAllowance;

		// parse expiration Date
		const xt_expiration = new Date(s_expiration!).getTime();

		// calculate time remaining
		const xt_remaining = xt_expiration - Date.now();

		// amount is still full
		if(a_limits?.[0]?.amount === `${XG_ALLOWANCE}`) {
			// feegrant still has more than an hour left
			if(xt_remaining > 36e5) {
				return (d_res.writeHead(400).write(stringify_json({
					error: `Existing feegrant is full and hasn't expired yet`,
				})), d_res.end());
			}
		}

		// revoke previous allowance
		const atu8_msg = encodeGoogleProtobufAny(
			SI_MESSAGE_TYPE_COSMOS_FEEGRANT_MSG_REVOKE_ALLOWANCE,
			encodeCosmosFeegrantMsgRevokeAllowance(
				K_SIGNER.addr,
				sa_grantee
			)
		);

		// execute revocation
		const [xc_code, s_error, g_meta, atu8_result, h_events] = await enqueue(atu8_msg, XG_LIMIT_REVOKE, sa_grantee);

		// error revoking
		if(xc_code) {
			return (d_res.writeHead(425).write(stringify_json({
				error: `Failed to revoke existing feegrant; reason: ${s_error}`,
			})), d_res.end());
		}

		// renewed claim
		y_counter_claims_renewed.inc();

		// success
		return (d_res.writeHead(200).write(stringify_json({
			meta: g_meta,
			events: h_events,
		})), d_res.end());
	}

	// generate message
	const atu8_msg = encodeGoogleProtobufAny(
		SI_MESSAGE_TYPE_COSMOS_FEEGRANT_MSG_GRANT_ALLOWANCE,
		encodeCosmosFeegrantMsgGrantAllowance(
			K_SIGNER.addr,
			sa_grantee,
			anyBasicAllowance([
				[`${500000n}`, 'uscrt'],
			], Date.now() + (24 * 36e5))
		)
	);

	// broadcast
	const [xc_code, s_error, g_meta, atu8_result, h_events] = await enqueue(atu8_msg, XG_LIMIT_GRANT, sa_grantee);

	// failed
	if(xc_code) {
		console.error(`<== 550 to ${sa_grantee}`);
		return (d_res.writeHead(550).write(s_error), d_res.end());
	}

	// issued claim
	y_counter_claims_issued.inc();

	// success
	return (d_res.writeHead(200).write(stringify_json({
		meta: g_meta,
		events: h_events,
	})), d_res.end());
}


await server({
	host: process.env['SERVER_HOST'],
	port: process.env['SERVER_PORT'],
	ready: () => true,
	health: () => true,
	handlers: {
		// OPTIONS
		options: {
			// for CORS requests
			'/claim/:address': async(d_req, d_res) => {
				// set response headers
				d_res.setHeaders(new Map([
					['access-control-allow-origin', '*'],
					['access-control-allow-methods', 'GET'],
				]));

				// return response
				return d_res.writeHead(204).end();
			}
		},

		// GET
		get: {
			// claim action
			'/claim/:address': async(d_req, d_res, h_params_query, h_params_path) => {
				// ref grantee address
				const sa_grantee = h_params_path['address'] as WeakSecretAccAddr;

				// execute claim
				return await claim(d_req, d_res, sa_grantee);
			},
		},

		// POST
		post: {
			// for backwards-compatibility
			'/claim': async(d_req, d_res, h_params_query, h_params_path) => {
				// prep to read body bytes
				const a_parts: Uint8Array[] = [];

				// read body
				for await (const ab_chunk of d_req) a_parts.push(ab_chunk);

				// parse JSON
				const g_json = parse_json_safe(bytes_to_text(concat(a_parts)));

				// destructure grantee address
				const {
					address: sa_grantee,
				} = g_json as {
					address: WeakSecretAccAddr;
				};

				// execute claim
				return await claim(d_req, d_res, sa_grantee);
			},
		},
	},
	metrics: [
		y_counter_claims_requested,
		y_counter_claims_existing,
		y_counter_claims_renewed,
		y_counter_claims_issued,
		y_counter_tx_broadcast_successes,
		y_counter_tx_broadcast_errors,
		y_gauge_block_height,
		y_gauge_uscrt_balance,
	],
})

console.log(`Feegrant wallet address: ${K_SIGNER.addr} on ${SI_CHAIN_ID}`);
