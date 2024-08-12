import type {WeakSecretAccAddr} from '@solar-republic/neutrino';

import {__UNDEFINED, assign, die, entries, hex_to_bytes, parse_json_safe, stringify_json, type Dict} from '@blake.regalia/belt';
import {SI_MESSAGE_TYPE_COSMOS_FEEGRANT_BASIC_ALLOWANCE, anyBasicAllowance, type CosmosFeegrantBasicAllowance} from '@solar-republic/cosmos-grpc/cosmos/feegrant/v1beta1/feegrant';
import {SI_MESSAGE_TYPE_COSMOS_FEEGRANT_MSG_GRANT_ALLOWANCE, SI_MESSAGE_TYPE_COSMOS_FEEGRANT_MSG_REVOKE_ALLOWANCE, encodeCosmosFeegrantMsgGrantAllowance, encodeCosmosFeegrantMsgRevokeAllowance} from '@solar-republic/cosmos-grpc/cosmos/feegrant/v1beta1/tx';
import {encodeGoogleProtobufAny} from '@solar-republic/cosmos-grpc/google/protobuf/any';

import {bech32_decode} from '@solar-republic/crypto';
import {TendermintEventFilter, Wallet, broadcast_result, create_and_sign_tx_direct, exec_fees} from '@solar-republic/neutrino';
import fastify, { type FastifyReply, type FastifyRequest } from 'fastify';
import { queryCosmosFeegrantAllowance } from '@solar-republic/cosmos-grpc/cosmos/feegrant/v1beta1/query';
import assert from 'assert';

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

async function exec_msgs(
	atu8_msg: Uint8Array,
	xg_limit: bigint,
) {
	// create and sign tx
	const [atu8_raw, atu8_signdoc, si_txn] = await create_and_sign_tx_direct(k_wallet, [atu8_msg], exec_fees(xg_limit, X_GAS_PRICE), `${xg_limit}`, 0, S_MEMO);

	// broadcast
	return await broadcast_result(k_wallet, atu8_raw, si_txn);
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
		const [xc_code, sx_res, g_meta, atu8_result, h_events] = await exec_msgs(atu8_msg, XG_LIMIT_REVOKE);

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

	// create and sign tx
	const [atu8_raw, atu8_signdoc, si_txn] = await create_and_sign_tx_direct(k_wallet, [atu8_msg], exec_fees(XG_LIMIT_GRANT, X_GAS_PRICE), `${XG_LIMIT_GRANT}`, 0, S_MEMO);

	// broadcast
	const [xc_code, sx_res, g_meta, atu8_result, h_events] = await broadcast_result(k_wallet, atu8_raw, si_txn, K_TEF_SECRET);

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
});
