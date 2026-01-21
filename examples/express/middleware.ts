/**
 * Express middleware for typesecure request/response sanitization.
 *
 * @example
 * ```ts
 * import express from "express";
 * import { typesecureMiddleware } from "./middleware";
 *
 * const app = express();
 * app.use(express.json());
 * app.use(typesecureMiddleware());
 * ```
 */

import type { Request, Response, NextFunction } from "express";
import {
  type Policy,
  defaultPolicy,
  assertAllowed,
  redact,
  safeJsonStringify,
  token,
  piiText,
  type TokenString,
} from "typesecure";

export interface TypesecureMiddlewareOptions {
  /**
   * Policy to use for request/response validation.
   * Defaults to defaultPolicy().
   */
  policy?: Policy;

  /**
   * Whether to redact request body before logging.
   * Defaults to true.
   */
  redactRequestBody?: boolean;

  /**
   * Whether to redact response body before logging.
   * Defaults to true.
   */
  redactResponseBody?: boolean;

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
 * Express middleware that:
 * 1. Classifies Authorization header as TokenString
 * 2. Validates request/response data against policy
 * 3. Provides redacted versions for logging
 *
 * @param options - Middleware configuration options
 * @returns Express middleware function
 */
export function typesecureMiddleware(
  options: TypesecureMiddlewareOptions = {},
): (req: Request, res: Response, next: NextFunction) => void {
  const {
    policy = defaultPolicy(),
    redactRequestBody = true,
    redactResponseBody = true,
    classifyAuthHeader = true,
    extractToken = (header: string) => {
      const match = header.match(/^Bearer\s+(.+)$/i);
      return match ? match[1] : null;
    },
  } = options;

  return (req: Request, res: Response, next: NextFunction): void => {
    // Classify Authorization header if present
    if (classifyAuthHeader && req.headers.authorization) {
      const tokenValue = extractToken(req.headers.authorization);
      if (tokenValue) {
        try {
          const classifiedToken = token(tokenValue);
          // Store on request for later use
          (req as Request & { typesecureToken?: TokenString }).typesecureToken =
            classifiedToken;
          // Validate token can be used in network context
          assertAllowed(policy, "network", { token: classifiedToken });
        } catch (error) {
          // If token classification fails, continue without it
          // (e.g., empty token or invalid format)
        }
      }
    }

    // Add redacted versions to request for safe logging
    if (redactRequestBody && req.body) {
      (req as Request & { redactedBody?: unknown }).redactedBody = redact(
        req.body,
      );
    }

    // Intercept response.json to redact before sending (optional)
    const originalJson = res.json.bind(res);
    res.json = function (body?: unknown): Response {
      if (redactResponseBody && body) {
        const redactedBody = redact(body);
        // Validate response can be sent over network
        try {
          assertAllowed(policy, "network", body);
        } catch (error) {
          // Log policy violation but don't block response
          console.warn("Policy violation in response:", error);
        }
        return originalJson(redactedBody);
      }
      return originalJson(body);
    };

    // Add helper methods to response
    (res as Response & {
      safeJson: (body: unknown) => Response;
      safeLog: (level: "info" | "warn" | "error", ...args: unknown[]) => void;
    }).safeJson = function (body: unknown): Response {
      try {
        assertAllowed(policy, "network", body);
      } catch (error) {
        console.warn("Policy violation:", error);
      }
      return this.json(redact(body));
    };

    (res as Response & {
      safeLog: (level: "info" | "warn" | "error", ...args: unknown[]) => void;
    }).safeLog = function (
      level: "info" | "warn" | "error",
      ...args: unknown[]
    ): void {
      try {
        assertAllowed(policy, "log", args);
        const redacted = args.map((a) => redact(a));
        console[level](...redacted);
      } catch (error) {
        console.warn("Policy violation in logging:", error);
      }
    };

    next();
  };
}

/**
 * Helper to safely log request information.
 *
 * @param req - Express request object
 * @param policy - Policy to use for validation
 * @param logger - Logger instance (defaults to console)
 *
 * @example
 * ```ts
 * app.get("/users/:id", (req, res) => {
 *   logRequest(req, policy);
 *   // ... handler logic
 * });
 * ```
 */
export function logRequest(
  req: Request,
  policy: Policy = defaultPolicy(),
  logger: Console = console,
): void {
  const data = {
    method: req.method,
    path: req.path,
    query: req.query,
    body: (req as Request & { redactedBody?: unknown }).redactedBody ?? req.body,
    headers: redact(req.headers),
  };

  try {
    assertAllowed(policy, "log", data);
    logger.info("Request:", safeJsonStringify(data, undefined, 2));
  } catch (error) {
    logger.warn("Request logging blocked by policy:", error);
  }
}
