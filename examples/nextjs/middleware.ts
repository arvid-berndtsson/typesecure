/**
 * Next.js middleware for typesecure request sanitization.
 *
 * @example
 * ```ts
 * // middleware.ts (Next.js 13+ App Router)
 * import { typesecureMiddleware } from "./middleware";
 * export default typesecureMiddleware();
 * export const config = { matcher: "/api/:path*" };
 * ```
 */

import type { NextRequest, NextResponse } from "next/server";
import {
  type Policy,
  defaultPolicy,
  assertAllowed,
  redact,
  token,
  type TokenString,
} from "typesecure";

export interface TypesecureNextMiddlewareOptions {
  /**
   * Policy to use for request validation.
   * Defaults to defaultPolicy().
   */
  policy?: Policy;

  /**
   * Whether to extract and classify Authorization header.
   * Defaults to true.
   */
  classifyAuthHeader?: boolean;

  /**
   * Custom function to extract token from Authorization header.
   * Defaults to extracting Bearer tokens.
   */
  extractToken?: (authHeader: string) => string | null;
}

/**
 * Next.js middleware that classifies and validates requests.
 *
 * @param options - Middleware configuration options
 * @returns Next.js middleware function
 */
export function typesecureMiddleware(
  options: TypesecureNextMiddlewareOptions = {},
) {
  const {
    policy = defaultPolicy(),
    classifyAuthHeader = true,
    extractToken = (header: string) => {
      const match = header.match(/^Bearer\s+(.+)$/i);
      return match ? match[1] : null;
    },
  } = options;

  return (req: NextRequest): NextResponse | void => {
    // Classify Authorization header if present
    if (classifyAuthHeader) {
      const authHeader = req.headers.get("authorization");
      if (authHeader) {
        const tokenValue = extractToken(authHeader);
        if (tokenValue) {
          try {
            const classifiedToken = token(tokenValue);
            // Validate token can be used in network context
            assertAllowed(policy, "network", { token: classifiedToken });
            // Store in request headers for API routes to access
            req.headers.set(
              "x-typesecure-token",
              JSON.stringify({ kind: "token", value: tokenValue }),
            );
          } catch (error) {
            // If token classification fails, continue without it
          }
        }
      }
    }

    // Continue to next middleware/handler
    return undefined;
  };
}

/**
 * Helper to extract classified token from Next.js request headers.
 *
 * @param req - Next.js request object
 * @returns Classified token if present, undefined otherwise
 */
export function getClassifiedToken(
  req: NextRequest | { headers: Headers },
): TokenString | undefined {
  const tokenHeader = req.headers.get("x-typesecure-token");
  if (tokenHeader) {
    try {
      const parsed = JSON.parse(tokenHeader);
      return token(parsed.value);
    } catch {
      return undefined;
    }
  }
  return undefined;
}
