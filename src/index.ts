import { Hono } from "hono";
import { setCookie } from "hono/cookie";
import { createProtectedRoute, type ProtectedRouteConfig } from "./auth";
import { generateJWT } from "./jwt";
import { hasBotManagementException } from "./bot-management";
import type { AppContext, Env } from "./env";

const app = new Hono<AppContext>();

const BUILTIN_PROTECTED_PATHS: ProtectedRouteConfig[] = [
	{
		pattern: "/__x402/protected",
		price: "$0.01",
		description: "Access to test protected endpoint",
	},
];

const BUILT_IN_PUBLIC_PATHS = ["/__x402/health", "/__x402/config"];

function getRawPath(url: string): string {
	const authorityStart = url.indexOf("://");
	const pathStart = url.indexOf("/", authorityStart + 3);
	if (pathStart === -1) {
		return "/";
	}

	const queryStart = url.indexOf("?", pathStart);
	return url.slice(pathStart, queryStart === -1 ? undefined : queryStart);
}

function hasNonCanonicalPath(url: string): boolean {
	const rawPath = getRawPath(url);
	return rawPath !== new URL(url).pathname || rawPath.includes("//");
}

async function proxyToOrigin(request: Request, env: Env): Promise<Response> {
	if (env.ORIGIN_SERVICE) {
		return env.ORIGIN_SERVICE.fetch(request);
	}

	if (env.ORIGIN_URL) {
		const originalUrl = new URL(request.url);
		const targetUrl = new URL(env.ORIGIN_URL);

		const proxiedUrl = new URL(request.url);
		proxiedUrl.hostname = targetUrl.hostname;
		proxiedUrl.protocol = targetUrl.protocol;
		proxiedUrl.port = targetUrl.port;

		const response = await fetch(proxiedUrl, {
			method: request.method,
			headers: request.headers,
			body: request.body,
			redirect: "manual",
		});

		const location = response.headers.get("Location");
		if (location) {
			try {
				const locationUrl = new URL(location, proxiedUrl);
				locationUrl.hostname = originalUrl.hostname;
				locationUrl.protocol = originalUrl.protocol;
				locationUrl.port = originalUrl.port;

				const newHeaders = new Headers(response.headers);
				newHeaders.set("Location", locationUrl.toString());

				return new Response(response.body, {
					status: response.status,
					statusText: response.statusText,
					headers: newHeaders,
				});
			} catch {
				// Return response as-is if redirect URL parsing fails.
			}
		}

		return response;
	}

	return fetch(request);
}

function pathMatchesPattern(path: string, pattern: string): boolean {
	if (pattern.endsWith("/*")) {
		const prefix = pattern.slice(0, -2);
		return path === prefix || path.startsWith(`${prefix}/`);
	}
	return path === pattern;
}

function findProtectedRouteConfig(
	path: string,
	patterns: ProtectedRouteConfig[]
): ProtectedRouteConfig | null {
	const allRoutes = [...BUILTIN_PROTECTED_PATHS, ...patterns];
	return (
		allRoutes.find((config) => pathMatchesPattern(path, config.pattern)) ?? null
	);
}

function addBazaarMetadata(response: Response, path: string): Response {
	if (response.status !== 402 || path !== "/evidence-check") {
		return response;
	}

	const encoded = response.headers.get("payment-required");
	if (!encoded) {
		return response;
	}

	try {
		const paymentRequired = JSON.parse(atob(encoded));
		paymentRequired.extensions = {
			...(paymentRequired.extensions || {}),
			bazaar: {
				info: {
					input: {
						type: "http",
						method: "POST",
						bodyType: "json",
						body: {
							question: "Does creatine improve strength in healthy adults?",
						},
					},
					output: {
						type: "json",
						example: {
							status: "complete",
							answer: "Evidence-based answer",
							confidence: 0.9,
							evidence: ["Supporting evidence"],
							uncertainty: [],
							sources: [],
						},
					},
				},
				schema: {
					type: "object",
					properties: {
						input: { type: "object" },
						output: { type: "object" },
					},
					required: ["input", "output"],
				},
			},
		};

		if (paymentRequired.resource) {
			paymentRequired.resource.serviceName = "A2A Evidence Check";
			paymentRequired.resource.tags = ["evidence", "research", "analysis", "ai-agent"];
		}

		const headers = new Headers(response.headers);
		headers.set("payment-required", btoa(JSON.stringify(paymentRequired)));
		return new Response(response.body, {
			status: response.status,
			statusText: response.statusText,
			headers,
		});
	} catch {
		return response;
	}
}

app.use("*", async (c, next) => {
	if (hasNonCanonicalPath(c.req.url)) {
		return c.json({ error: "Non-canonical request path" }, 400);
	}

	const path = c.req.path;
	const protectedPatterns = c.env.PROTECTED_PATTERNS || [];

	if (BUILT_IN_PUBLIC_PATHS.includes(path)) {
		return next();
	}

	const protectedConfig = findProtectedRouteConfig(path, protectedPatterns);
	if (protectedConfig) {
		if (hasBotManagementException(c.req.raw, protectedConfig)) {
			if (path === "/__x402/protected") {
				return next();
			}
			return proxyToOrigin(c.req.raw, c.env);
		}

		if (!c.env.JWT_SECRET) {
			return c.json(
				{
					error:
						"Server misconfigured: JWT_SECRET not set. See README for setup instructions.",
				},
				500
			);
		}

		const protectedMiddleware = createProtectedRoute(protectedConfig);
		let jwtToken = "";

		const result = await protectedMiddleware(c, async () => {
			const hasExistingAuth = c.get("auth");

			if (!hasExistingAuth) {
				jwtToken = await generateJWT(c.env.JWT_SECRET, 3600);
			}
		});

		if (result) {
			return addBazaarMetadata(result, path);
		}

		if (c.res && c.res.status >= 400) {
			return addBazaarMetadata(c.res, path);
		}

		if (path === "/__x402/protected") {
			if (jwtToken) {
				setCookie(c, "auth_token", jwtToken, {
					httpOnly: true,
					secure: true,
					sameSite: "Strict",
					maxAge: 3600,
					path: "/",
				});
			}

			await next();
			return c.res;
		}

		const originResponse = await proxyToOrigin(c.req.raw, c.env);

		if (jwtToken) {
			setCookie(c, "auth_token", jwtToken, {
				httpOnly: true,
				secure: true,
				sameSite: "Strict",
				maxAge: 3600,
				path: "/",
			});

			const newResponse = new Response(originResponse.body, {
				status: originResponse.status,
				statusText: originResponse.statusText,
				headers: new Headers(originResponse.headers),
			});

			const setCookieHeaders = c.res.headers.getSetCookie();
			for (const cookie of setCookieHeaders) {
				newResponse.headers.append("Set-Cookie", cookie);
			}

			return newResponse;
		}

		return originResponse;
	}

	return proxyToOrigin(c.req.raw, c.env);
});

app.get("/__x402/health", (c) => {
	return c.json({
		status: "ok",
		proxy: "x402-proxy",
		message: "This endpoint is always public",
		timestamp: Date.now(),
	});
});

app.get("/__x402/config", (c) => {
	const patterns = (c.env.PROTECTED_PATTERNS || []) as ProtectedRouteConfig[];
	const botFilteringEnabled = patterns.some(
		(p) => p.bot_score_threshold !== undefined
	);

	return c.json({
		network: c.env.NETWORK,
		payTo: c.env.PAY_TO ? `***${c.env.PAY_TO.slice(-6)}` : null,
		hasOriginUrl: !!c.env.ORIGIN_URL,
		hasOriginService: !!c.env.ORIGIN_SERVICE,
		protectedPatterns: patterns.map((p) => ({
			pattern: p.pattern,
			botManagementFiltering:
				p.bot_score_threshold !== undefined
					? {
							threshold: p.bot_score_threshold,
							exceptionsCount: p.except_detection_ids?.length ?? 0,
						}
					: null,
		})),
		botManagementFiltering: botFilteringEnabled,
	});
});

app.get("/__x402/protected", (c) => {
	return c.json({
		message: "Premium content accessed!",
		timestamp: Date.now(),
		note: "This endpoint always requires payment or valid authentication cookie",
	});
});

export default app;
