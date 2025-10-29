import type {Dict, Promisable} from '@blake.regalia/belt';
import type {Metric} from 'prom-client';
import {from_entries, defer, transform_values, entries, escape_regex, collapse} from '@blake.regalia/belt';
import {IncomingMessage, ServerResponse, type Server, createServer} from 'http';
import {Registry, collectDefaultMetrics} from 'prom-client';
import {S_METRICS_AUTH_PASSWORD, SB64_METRICS_AUTH} from './feegrant';

type RouteHandler = (
	d_req: IncomingMessage,
	d_res: ServerResponse<IncomingMessage>,
	h_params_query: Dict,
	h_params_path: Dict
) => Promisable<any>;

// path param regex
export const R_PATH_PARAM = /^([^:]*?)(\/:[a-zA-Z_][a-zA-Z0-9_]*)([^:]*)$/;

// parse authorization header
export const R_HEADER_AUTH_BASIC = /^Basic\s+(\S+)$/;


/**
 * Creates a simple HTTP server that responds to readiness and health probes
 */
export async function server(gc_probe: {
	host?: undefined | string;
	port?: undefined | number | string;
	ready?: () => Promisable<boolean>;
	health?: () => Promisable<boolean>;
	metrics?: Metric[];
	handlers: {
		options?: Dict<RouteHandler>;
		get?: Dict<RouteHandler>;
		post?: Dict<RouteHandler>;
	};
}): Promise<{
	server: Server;
	registry: undefined | Registry;
}> {
	// destructure
	const {
		handlers: h_handlers,
	} = gc_probe;

	// extend with default GET request router
	const h_router_get: Dict<RouteHandler> = {
		...gc_probe.ready ? {'/ready': async (d_req, d_res) => d_res.writeHead(await gc_probe.ready!() ? 200 : 500).end()} : {},
		...gc_probe.health ? {'/healthz': async (d_req, d_res) => d_res.writeHead(await gc_probe.health!() ? 200 : 500).end()} : {},
		...h_handlers.get,
	};

	// prep prometheus registry
	let y_registry: undefined | Registry;

	// metrics defined
	if (gc_probe.metrics) {
		// create prometheus metrics registry
		y_registry = new Registry();

		// collect default metrics from node.js
		collectDefaultMetrics({register: y_registry});

		// register additional metrics
		for (const y_metric of gc_probe.metrics) {
			y_registry.registerMetric(y_metric);
		}

		// serve metrics
		h_router_get['/metrics'] = async (d_req, d_res) => {
			// metrics are guarded by auth
			if (S_METRICS_AUTH_PASSWORD) {
				// parse basic auth
				const [_, sb64_encoded] = R_HEADER_AUTH_BASIC.exec(d_req.headers.authorization || '') || [];

				// invalid auth
				if (sb64_encoded.replace(/=+/, '') !== SB64_METRICS_AUTH) return d_res.writeHead(401).end();
			}

			// serve metrics
			d_res.writeHead(200, {'Content-Type': 'text/plain'}).end(await y_registry!.metrics());
		};
	}

	// convert each handler to matcher
	const h_routers = transform_values({
		...h_handlers,
		get: h_router_get,
	}, (h_handler) => entries(h_handler ?? {}).map(([sx_route, f_handler]) => {
		// prep route regex
		let r_route: RegExp;

		// prep param names
		let a_params: string[] = [];

		// match path param
		const m_param = R_PATH_PARAM.exec(sx_route);
		if(m_param) {
			const [_, s_prefix, s_param, s_suffix] = m_param;

			// construct regex
			r_route = new RegExp(`^${escape_regex(s_prefix)}/([^/]+)${escape_regex(s_suffix)}$`);

			// param names
			a_params = [s_param];
		}
		// exact match
		else {
			r_route = new RegExp(`^${escape_regex(sx_route)}$`);
		}

		// return values
		return [r_route, a_params, f_handler] as const;
	}));

	// create server
	const d_server = createServer(async (d_req, d_res) => {
		// attempt to parse body and route request
		try {
			// validate path
			if ('/' !== d_req.url?.[0]) throw new Error('Invalid path');

			// parse request path and query params
			const [s_path, sx_params] = d_req.url.split('?');

			// normalize method
			const si_method = d_req.method?.toLowerCase() ?? '';

			// method not supported
			if (!(si_method in h_routers)) return d_res.writeHead(405).end();

			// ref method handlers
			const h_method = h_routers[si_method as keyof typeof h_routers];
			if (h_method) {
				// each handler
				for (const [r_route, a_param_names, f_handler] of h_method) {
					// match
					const m_route = r_route.exec(s_path);
					if(m_route) {
						// extract param values
						const a_param_values = m_route.slice(1);

						// map to path param names
						const h_params_path = collapse(a_param_names, (s_name, i_each) => [s_name.replace(/^\/:/, ''), a_param_values[i_each]] as const);

						// parse query params
						const h_params_query = from_entries(new URLSearchParams(sx_params).entries());

						// forward to handler
						return await f_handler(d_req, d_res, h_params_query, h_params_path);
					}
				}
			}

			// handler not found
			return d_res.writeHead(404).end();
		}
		// server error
		catch (_e_route) {
			console.error(_e_route);

			return d_res.writeHead(500).end();
		}
	});

	// create deferred Promise
	const [dp_ready, fke_ready] = defer<void>();

	// listen on port
	d_server.listen({
		host: gc_probe.host || '127.0.0.1',
		port: gc_probe.port || 8080,
	}, () => {
		// verbose
		console.info(`Probe server listening on port ${gc_probe.port}`);

		// resolve ready Promise
		fke_ready(void 0);
	});

	// wait for server to be ready
	await dp_ready;

	// return values
	return {
		server: d_server,
		registry: y_registry,
	};
}
