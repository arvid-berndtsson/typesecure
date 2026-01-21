/**
 * Next.js App Router example using typesecure.
 *
 * File structure:
 * - middleware.ts (root)
 * - app/api/users/route.ts
 * - app/api/auth/login/route.ts
 */

// middleware.ts (at root of Next.js app)
/*
import { typesecureMiddleware } from "./examples/nextjs/middleware";
import { defaultPolicy } from "typesecure";

export default typesecureMiddleware({ policy: defaultPolicy() });

export const config = {
  matcher: "/api/:path*",
};
*/

// app/api/users/route.ts
/*
import { createSafeApiHandler, safeLog } from "./examples/nextjs/api-helpers";
import { piiText, publicText, defaultPolicy } from "typesecure";

const policy = defaultPolicy();

export const POST = createSafeApiHandler(async (req) => {
  const body = await req.json();
  const { email, name } = body;

  // Classify user data
  const userEmail = piiText(email);
  const userName = piiText(name);

  // Validate storage (PII allowed)
  assertAllowed(policy, "storage", { email: userEmail, name: userName });

  // Safe logging
  safeLog(policy, "info", "User created", { email: userEmail });

  // Response will be automatically redacted
  return Response.json({
    message: publicText("User created successfully"),
    userId: 123,
    email: userEmail, // Will be redacted
  });
});

export const GET = createSafeApiHandler(async (req) => {
  const { searchParams } = new URL(req.url);
  const userId = searchParams.get("id");

  safeLog(policy, "info", "Fetching user", { userId });

  // Response will be automatically redacted
  return Response.json({
    id: userId,
    email: piiText("user@example.com"), // Will be redacted
    name: piiText("John Doe"), // Will be redacted
  });
});
*/

// app/api/auth/login/route.ts
/*
import { createSafeApiHandler } from "./examples/nextjs/api-helpers";
import { token, publicText, defaultPolicy } from "typesecure";

const policy = defaultPolicy();

export const POST = createSafeApiHandler(async (req) => {
  const { email, password } = await req.json();

  // In a real app, verify credentials
  const sessionToken = token("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...");

  // Token can be sent over network (allowed by default policy)
  return Response.json({
    message: publicText("Login successful"),
    token: sessionToken, // Will be redacted in response
  });
});
*/

export {};
