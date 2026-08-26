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
		// Check for valid cookie
		const token = getCookie(c, "auth_token");

		if (token) {
			const jwtSecret = c.env.JWT_SECRET;

			// Ensure JWT_SECRET is configured
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

			// If token is valid, skip payment and go directly to handler
			if (payload) {
				c.set("auth", payload);
				await next(); // Call the handler
				return;
			}
		}

		// No valid cookie - apply payment middleware
		return await paymentMw(c, next);
	};
}

/**
 * Configuration for a protected route that requires payment
 */
export interface ProtectedRouteConfig {
	/** Route pattern to protect (e.g., "/premium", "/api/paid/*") */
	pattern: string;
	/** Price in USD (e.g. "$0.01") */
	price: string;
	/** Human-readable description of what the payment is for */
	description: string;
	/**
	 * Bot Management Filtering (optional)
	 * Requires Bot Management for Enterprise. See src/bot-management/ for details.
	 */
	bot_score_threshold?: number;
	except_detection_ids?: number[];
}

/**
 * Creates middleware for a protected route that requires payment OR valid cookie
 * This dynamically creates payment middleware at request time to access environment variables
 * The route path is automatically determined from the request context
 *
 * @param config - Payment configuration
 * @returns Middleware that enforces payment or cookie authentication
 */
export function createProtectedRoute(config: ProtectedRouteConfig) {
	return async (c: Context<AppContext>, next: Next) => {
		// Get the route path from the request context
		// Normalize the path by removing trailing slashes (except for root "/")
		// This matches how x402's findMatchingRoute normalizes incoming request paths
		const rawPath = c.req.path;
		const routePath =
			rawPath.length > 1 ? rawPath.replace(/\/+$/, "") : rawPath;

		// Create x402 v2 payment middleware
const facilitatorClient = new HTTPFacilitatorClient({
  url: c.env.FACILITATOR_URL || "https://x402.org/facilitator",
});

const server = new x402ResourceServer(facilitatorClient);

registerExactEvmScheme(server);

const paymentMw = paymentMiddleware(
  {
    [routePath]: {
      accepts: [
        {
          scheme: "exact",
          price: config.price,
          network: "eip155:84532",
          payTo: c.env.PAY_TO as `0x${string}`,
        },
      ],
      description: config.description,
      mimeType: "application/json",
    },
  },
  server,
);

		// Apply the combined auth/payment middleware
		return await requirePaymentOrCookie(paymentMw)(c, next);
	};
}
