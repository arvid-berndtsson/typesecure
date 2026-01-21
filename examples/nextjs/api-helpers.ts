/**
 * Next.js API route helpers for typesecure.
 *
 * @example
 * ```ts
 * // app/api/users/route.ts (App Router)
 * import { createSafeApiHandler } from "./api-helpers";
 *
 * export const POST = createSafeApiHandler(async (req, res) => {
 *   const { email } = await req.json();
 *   const userEmail = piiText(email);
 *   return res.json({ email: userEmail });
 * });
 * ```
 */

import type { NextRequest, NextResponse } from "next/server";
import {
  type Policy,
  defaultPolicy,
  assertAllowed,
  redact,
  safeJsonStringify,
  type PolicyAction,
} from "typesecure";

export interface SafeApiHandlerOptions {
  /**
   * Policy to use for validation.
   * Defaults to defaultPolicy().
   */
  policy?: Policy;

  /**
   * Actions to validate before handler execution.
   * Defaults to ["network"] for responses.
   */
  validateActions?: PolicyAction[];

  /**
   * Whether to automatically redact response data.
   * Defaults to true.
   */
  redactResponse?: boolean;
}

/**
 * Create a safe API route handler with automatic policy enforcement and redaction.
 *
 * @param handler - The API route handler function
 * @param options - Handler configuration options
 * @returns Next.js API route handler
 *
 * @example
 * ```ts
 * export const POST = createSafeApiHandler(async (req) => {
 *   const body = await req.json();
 *   const email = piiText(body.email);
 *   return Response.json({ email });
 * });
 * ```
 */
export function createSafeApiHandler(
  handler: (
    req: NextRequest,
    context?: { params?: Record<string, string> },
  ) => Promise<Response> | Response,
  options: SafeApiHandlerOptions = {},
): (
  req: NextRequest,
  context?: { params?: Record<string, string> },
) => Promise<Response> {
  const {
    policy = defaultPolicy(),
    validateActions = ["network"],
    redactResponse = true,
  } = options;

  return async (
    req: NextRequest,
    context?: { params?: Record<string, string> },
  ): Promise<Response> => {
    try {
      // Execute handler
      const response = await handler(req, context);

      // Validate response data if it's JSON
      const contentType = response.headers.get("content-type");
      if (contentType?.includes("application/json")) {
        const clonedResponse = response.clone();
        const data = await clonedResponse.json();

        // Validate against policy
        for (const action of validateActions) {
          assertAllowed(policy, action, data);
        }

        // Redact if configured
        if (redactResponse) {
          const redactedData = redact(data);
          return Response.json(redactedData, {
            status: response.status,
            headers: response.headers,
          });
        }
      }

      return response;
    } catch (error) {
      // Handle policy violations
      if (error instanceof Error && error.message.includes("Policy")) {
        return Response.json(
          { error: "Policy violation", message: error.message },
          { status: 403 },
        );
      }

      // Re-throw other errors
      throw error;
    }
  };
}

/**
 * Helper to safely log in API routes.
 *
 * @param policy - Policy to use for validation
 * @param level - Log level
 * @param args - Arguments to log
 *
 * @example
 * ```ts
 * safeLog(policy, "info", "User created", { email: piiText("user@example.com") });
 * ```
 */
export function safeLog(
  policy: Policy,
  level: "info" | "warn" | "error",
  ...args: unknown[]
): void {
  try {
    assertAllowed(policy, "log", args);
    const redacted = args.map((a) => redact(a));
    console[level](...redacted);
  } catch (error) {
    console.warn("Logging blocked by policy:", error);
  }
}

/**
 * Helper to safely stringify data for logging.
 *
 * @param data - Data to stringify
 * @param policy - Policy to use for validation
 * @returns JSON string with redacted data
 *
 * @example
 * ```ts
 * const logData = safeStringify({ email: piiText("user@example.com") }, policy);
 * console.log(logData);
 * ```
 */
export function safeStringify(
  data: unknown,
  policy: Policy = defaultPolicy(),
): string {
  try {
    assertAllowed(policy, "log", data);
    return safeJsonStringify(data, undefined, 2);
  } catch (error) {
    return `[Logging blocked: ${error instanceof Error ? error.message : "unknown"}]`;
  }
}
