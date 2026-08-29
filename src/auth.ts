/**
 * Authentication middleware for cookie-based JWT verification
 */

import { Context, Next, MiddlewareHandler } from "hono";
import { getCookie } from "hono/cookie";
import { verifyJWT } from "./jwt";
import { paymentMiddleware } from "@x402/hono";
import {
  HTTPFacilitatorClient,
  x402ResourceServer,
} from "@x402/core/server";
import { registerExactEvmScheme } from "@x402/evm/exact/server";
import type { AppContext } from "./env";

/**
 * Creates a combined middleware that checks for valid cookie authentication
 * and conditionally applies payment middleware only if cookie auth fails
 *
 * @param paymentMiddleware - The payment middleware to apply when no valid cookie exists
 * @returns Combined authentication and payment middleware
 */
export function requirePaymentOrCookie(paymentMw: MiddlewareHandler) {
	return async (c: Context<AppContext>, next: Next) => {
		const token = getCookie(c, "auth_token");

		if (token) {
			const jwtSecret = c.env.JWT_SECRET;

			if (!jwtSecret) {
				return c.json(
					{
						error:
							"Server misconfigured: JWT_SECRET not set. See README for setup instructions.",
					},
					500
				);
			}

			const payload = await verifyJWT(token, jwtSecret);

			if (payload) {
				c.set("auth", payload);
				await next();
				return;
			}
		}

		return await paymentMw(c, next);
	};
}

export interface ProtectedRouteConfig {
	pattern: string;
	price: string;
	description: string;
	bot_score_threshold?: number;
	except_detection_ids?: number[];
}

export function createProtectedRoute(config: ProtectedRouteConfig) {
	return async (c: Context<AppContext>, next: Next) => {
		const rawPath = c.req.path;
		const routePath =
			rawPath.length > 1 ? rawPath.replace(/\/+$/, "") : rawPath;

		const facilitatorClient = new HTTPFacilitatorClient({
			url: c.env.FACILITATOR_URL || "https://x402.org/facilitator",
		});

		const server = new x402ResourceServer(facilitatorClient);

		registerExactEvmScheme(server);

		const network =
			c.env.NETWORK === "base" ? "eip155:8453" : "eip155:84532";

		const paymentMw = paymentMiddleware(
			{
				[routePath]: {
					accepts: [
						{
							scheme: "exact",
							price: config.price,
							network,
							payTo: c.env.PAY_TO as `0x${string}`,
						},
					],
					description: config.description,
					mimeType: "application/json",
				},
			},
			server,
		);

		return await requirePaymentOrCookie(paymentMw)(c, next);
	};
}
