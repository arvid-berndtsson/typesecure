/**
 * Vercel Edge Function example using typesecure.
 *
 * @example
 * ```ts
 * // app/api/hello/route.ts
 * import { edgeHandler } from "./examples/edge/vercel-edge";
 * export const runtime = "edge";
 * export const GET = edgeHandler(async (req) => {
 *   return Response.json({ message: publicText("Hello from edge!") });
 * });
 * ```
 */

import type { NextRequest } from "next/server";
import {
  type Policy,
  defaultPolicy,
  assertAllowed,
  redact,
  token,
  type TokenString,
} from "typesecure";

export interface EdgeHandlerOptions {
  /**
   * Policy to use for validation.
   * Defaults to defaultPolicy().
   */
  policy?: Policy;

  /**
   * Whether to automatically redact response data.
   * Defaults to true.
   */
  redactResponse?: boolean;
}

/**
 * Create an edge-compatible API handler with typesecure.
 * Edge functions have limited APIs, so this uses only browser-compatible code.
 *
 * @param handler - The edge handler function
 * @param options - Handler options
 * @returns Edge-compatible handler
 */
export function edgeHandler(
  handler: (req: NextRequest) => Promise<Response> | Response,
  options: EdgeHandlerOptions = {},
): (req: NextRequest) => Promise<Response> {
  const { policy = defaultPolicy(), redactResponse = true } = options;

  return async (req: NextRequest): Promise<Response> => {
    try {
      // Execute handler
      const response = await handler(req);

      // Validate and redact response if JSON
      const contentType = response.headers.get("content-type");
      if (contentType?.includes("application/json") && redactResponse) {
        const clonedResponse = response.clone();
        const data = await clonedResponse.json();

        // Validate
        assertAllowed(policy, "network", data);

        // Redact
        const redactedData = redact(data);
        return Response.json(redactedData, {
          status: response.status,
          headers: response.headers,
        });
      }

      return response;
    } catch (error) {
      if (error instanceof Error && error.message.includes("Policy")) {
        return Response.json(
          { error: "Policy violation", message: error.message },
          { status: 403 },
        );
      }
      throw error;
    }
  };
}

/**
 * Extract and classify token from Authorization header (edge-compatible).
 *
 * @param req - Next.js request
 * @returns Classified token if present
 */
export function getEdgeToken(req: NextRequest): TokenString | undefined {
  const authHeader = req.headers.get("authorization");
  if (authHeader) {
    const match = authHeader.match(/^Bearer\s+(.+)$/i);
    if (match) {
      try {
        return token(match[1]);
      } catch {
        return undefined;
      }
    }
  }
  return undefined;
}
