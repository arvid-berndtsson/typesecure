/**
 * Cloudflare Worker example using typesecure.
 *
 * @example
 * ```ts
 * // worker.ts
 * import { cloudflareHandler } from "./examples/edge/cloudflare-worker";
 *
 * export default {
 *   async fetch(request: Request): Promise<Response> {
 *     return cloudflareHandler(async (req) => {
 *       return Response.json({ message: publicText("Hello from Cloudflare!") });
 *     })(request);
 *   }
 * };
 * ```
 */

import {
  type Policy,
  defaultPolicy,
  assertAllowed,
  redact,
  token,
  type TokenString,
} from "typesecure";

export interface CloudflareHandlerOptions {
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
 * Create a Cloudflare Worker handler with typesecure.
 *
 * @param handler - The handler function
 * @param options - Handler options
 * @returns Cloudflare Worker handler
 */
export function cloudflareHandler(
  handler: (request: Request) => Promise<Response> | Response,
  options: CloudflareHandlerOptions = {},
): (request: Request) => Promise<Response> {
  const { policy = defaultPolicy(), redactResponse = true } = options;

  return async (request: Request): Promise<Response> => {
    try {
      // Execute handler
      const response = await handler(request);

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
 * Extract and classify token from Authorization header.
 *
 * @param request - Request object
 * @returns Classified token if present
 */
export function getCloudflareToken(request: Request): TokenString | undefined {
  const authHeader = request.headers.get("authorization");
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
