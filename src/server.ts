import type {SlimAuthInfo, TxResultTuple, WeakSecretAccAddr} from '@solar-republic/neutrino';
import type {WeakUintStr} from '@solar-republic/types';

import {__UNDEFINED, assign, defer, die, entries, hex_to_bytes, parse_json_safe, stringify_json, type Dict} from '@blake.regalia/belt';
import {SI_MESSAGE_TYPE_COSMOS_FEEGRANT_BASIC_ALLOWANCE, anyBasicAllowance, type CosmosFeegrantBasicAllowance} from '@solar-republic/cosmos-grpc/cosmos/feegrant/v1beta1/feegrant';
import {SI_MESSAGE_TYPE_COSMOS_FEEGRANT_MSG_GRANT_ALLOWANCE, SI_MESSAGE_TYPE_COSMOS_FEEGRANT_MSG_REVOKE_ALLOWANCE, encodeCosmosFeegrantMsgGrantAllowance, encodeCosmosFeegrantMsgRevokeAllowance} from '@solar-republic/cosmos-grpc/cosmos/feegrant/v1beta1/tx';
import {encodeGoogleProtobufAny} from '@solar-republic/cosmos-grpc/google/protobuf/any';

import {bech32_decode} from '@solar-republic/crypto';
import {TendermintEventFilter, TendermintWs, Wallet, auth, broadcast_result, create_and_sign_tx_direct, exec_fees} from '@solar-republic/neutrino';
import fastify, { type FastifyReply, type FastifyRequest } from 'fastify';
import {queryCosmosFeegrantAllowance} from '@solar-republic/cosmos-grpc/cosmos/feegrant/v1beta1/query';
import assert from 'assert';

type BlockIdFrag = {
	hash: string;
	parts: {
		total: number;
		hash: string;
	};
}

// check server secret key
const SB16_SERVER_SK = (process.env.SERVER_SK || '').replace(/^0x/, '');
if(64 !== SB16_SERVER_SK.length) {
	throw Error(`Invalid server secret key; must be 64 hexadecimal digits. SERVER_SK is ${SB16_SERVER_SK? 'the wrong length': 'empty'}`);
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

// set optional memo
const S_MEMO = process.env.FEEGRANT_MEMO || '';

// gas limits
const XG_LIMIT_GRANT = 15_000n;
const XG_LIMIT_REVOKE = 15_000n;

// create server's feegranter wallet
const k_wallet = await Wallet(
	hex_to_bytes(process.env.SERVER_SK),
	'secret-4',
	process.env.SECRET_LCD,
	process.env.SECRET_RPC,
	'secret'
);

// open a persistent WebSocket to Secret RPC
const K_TEF_SECRET = await TendermintEventFilter(P_RPC_SECRET);

// create HTTP server
const y_fastify = fastify({
	logger: true,
});

// enqueued messaged
const a_enqueued: [
	atu8_msg: Uint8Array,
	xg_limit: bigint,
	fke_granted: ReturnType<typeof defer>[1],
][] = [];

// flag controls whether it should wait for account sequence to catch up
let c_clearing = 0;

// monitor when new block occurs
await TendermintWs(P_RPC_SECRET, `tm.event='NewBlock'`, async(d_event) => {
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
	console.log(`Block #${sg_height}; ${a_enqueued.length} enqueued`);

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

			// try processing
			try {
				// concat all messages
				const a_msgs = a_dequeued.map(([atu8]) => atu8);

				// compute sum of limits
				const xg_limit = a_dequeued.reduce((xg_sum, [, xg]) => xg_sum + xg, 0n);

				// create and sign tx
				const [atu8_raw, atu8_signdoc, si_txn] = await create_and_sign_tx_direct(k_wallet, a_msgs, exec_fees(xg_limit, X_GAS_PRICE), `${xg_limit}`, z_auth, S_MEMO);

				// broadcast
				a_results = await broadcast_result(k_wallet, atu8_raw, si_txn, K_TEF_SECRET);

				// destructure
				const [xc_code, sx_res, g_meta] = a_results;

				// verbose
				console.log(`${xc_code}: ${sx_res}`);

				// error
				if(xc_code) {
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
										const a_auth = await auth(k_wallet);

										// set auth
										z_auth = [a_auth[0], m_expected[1] as WeakUintStr];

										// verbose
										console.warn(`Auth info: ${z_auth[0]}, ${z_auth[1]}`);

										// retry
										continue RETRY_TRANSACTION;
									}
								}
							}

							break;
						}
					}
				}
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
		c_clearing = 2;
	}
}, 1);

// enqueue a message to be signed and broadcasted in next transaction
export async function enqueue(
	atu8_msg: Uint8Array,
	xg_limit: bigint,
): Promise<TxResultTuple> {
	// create deferred Promise
	const [dp_granted, fke_granted] = defer();

	// enqueue
	a_enqueued.push([
		atu8_msg,
		xg_limit,
		fke_granted,
	]);

	// return Promise
	return dp_granted;
}

// for CORS requests
y_fastify.options('/claim/:address', async(d_req, d_res) => {
	// set response headers
	d_res.headers({
		'access-control-allow-origin': '*',
		'access-control-allow-methods': 'GET',
	});

	return d_res.status(204).send();
});

// for the action
y_fastify.get<{
	Params: {
		address: string;
	};
}>('/claim/:address', async(d_req, d_res) => {
	// ref grantee address
	const sa_grantee = d_req.params.address as WeakSecretAccAddr;

	// execute claim
	return await claim(d_req, d_res, sa_grantee);
});

// for backwards-compatibility
y_fastify.post<{
	Params: {
		address: string;
	};
}>('/claim', async(d_req, d_res) => {
	// parse grantee address
	const {
		address: sa_grantee,
	} = d_req.body as {
		address: WeakSecretAccAddr;
	};

	// execute claim
	return await claim(d_req, d_res, sa_grantee);
});

async function claim(d_req: FastifyRequest, d_res: FastifyReply, sa_grantee: WeakSecretAccAddr) {
	// log request
	console.log(`${d_req.method} ${d_req.url} ${entries(d_req.query as Dict)}`);

	// set response headers
	d_res.headers({
		'access-control-allow-origin': '*',
		'access-control-allow-methods': 'GET',
	});

	// verify address
	try {
		if(!sa_grantee.startsWith('secret1')) die('');
		const atu8_data = bech32_decode(sa_grantee);
		assert(20 === atu8_data.length);
	}
	catch(e_decode) {
		return d_res.code(400).send({
			error: 'Invalid bech32 address',
		});
	}

	// check if user has existing feegrant
	const [,, g_res_allowance] = await queryCosmosFeegrantAllowance(k_wallet.lcd, k_wallet.addr, sa_grantee);

	// existing feegrant
	if(g_res_allowance?.allowance) {
		const g_allowance = g_res_allowance.allowance.allowance;

		// check allowance type
		if(SI_MESSAGE_TYPE_COSMOS_FEEGRANT_BASIC_ALLOWANCE !== g_allowance?.['@type']) {
			return d_res.code(500).send({
				error: `Discovered non-basic allowance`,
			});
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
				return d_res.code(400).send({
					error: `Existing feegrant is full and hasn't expired yet`,
				});
			}
		}
	
		// revoke previous allowance
		const atu8_msg = encodeGoogleProtobufAny(
			SI_MESSAGE_TYPE_COSMOS_FEEGRANT_MSG_REVOKE_ALLOWANCE,
			encodeCosmosFeegrantMsgRevokeAllowance(
				k_wallet.addr,
				sa_grantee
			)
		);

		// execute revocation
		const [xc_code, sx_res, g_meta, atu8_result, h_events] = await enqueue(atu8_msg, XG_LIMIT_REVOKE);

		// error revoking
		if(xc_code) {
			return d_res.code(425).send({
				error: `Failed to revoke existing feegrant; reason: ${sx_res}`,
			});
		}
	}

	// generate message
	const atu8_msg =  encodeGoogleProtobufAny(
		SI_MESSAGE_TYPE_COSMOS_FEEGRANT_MSG_GRANT_ALLOWANCE,
		encodeCosmosFeegrantMsgGrantAllowance(
			k_wallet.addr,
			sa_grantee,
			anyBasicAllowance([
				[`${500000n}`, 'uscrt'],
			], Date.now() + (24 * 36e5))
		)
	);

	// broadcast
	const [xc_code, sx_res, g_meta, atu8_result, h_events] = await enqueue(atu8_msg, XG_LIMIT_GRANT);

	// failed
	if(xc_code) {
		console.error(`code:${xc_code}; res:${sx_res}; meta:${stringify_json(g_meta)}`);
		return d_res.code(550).send(parse_json_safe(sx_res) || sx_res);
	}

	// success
	return d_res.code(200).send({
		meta: g_meta,
		events: h_events,
	});
}

// bind to WAN
y_fastify.listen({
	host: process.env.SERVER_HOST || 'localhost',
	port: parseInt(process.env.SERVER_PORT || '3001'),
}, (e_report) => {
	if(!e_report) {
		console.log(`Feegrant wallet address: ${k_wallet.addr}`);
	}
	else {
		console.error(e_report);
	}
});
