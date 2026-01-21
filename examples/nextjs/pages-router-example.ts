/**
 * Next.js Pages Router example using typesecure.
 *
 * File structure:
 * - pages/api/users.ts
 * - pages/api/auth/login.ts
 */

// pages/api/users.ts
/*
import type { NextApiRequest, NextApiResponse } from "next";
import {
  piiText,
  publicText,
  defaultPolicy,
  assertAllowed,
  redact,
  safeJsonStringify,
} from "typesecure";
import { safeLog } from "./examples/nextjs/api-helpers";

const policy = defaultPolicy();

export default function handler(
  req: NextApiRequest,
  res: NextApiResponse,
) {
  if (req.method === "POST") {
    const { email, name } = req.body;

    // Classify user data
    const userEmail = piiText(email);
    const userName = piiText(name);

    // Validate storage
    assertAllowed(policy, "storage", { email: userEmail, name: userName });

    // Safe logging
    safeLog(policy, "info", "User created", { email: userEmail });

    // Validate and redact response
    try {
      assertAllowed(policy, "network", { email: userEmail });
      const response = {
        message: publicText("User created successfully"),
        userId: 123,
        email: userEmail,
      };
      const redactedResponse = redact(response);
      res.status(200).json(redactedResponse);
    } catch (error) {
      res.status(403).json({ error: "Policy violation" });
    }
  } else if (req.method === "GET") {
    const userId = req.query.id as string;

    safeLog(policy, "info", "Fetching user", { userId });

    const response = {
      id: userId,
      email: piiText("user@example.com"),
      name: piiText("John Doe"),
    };

    try {
      assertAllowed(policy, "network", response);
      const redactedResponse = redact(response);
      res.status(200).json(redactedResponse);
    } catch (error) {
      res.status(403).json({ error: "Policy violation" });
    }
  } else {
    res.status(405).json({ error: "Method not allowed" });
  }
}
*/

// pages/api/auth/login.ts
/*
import type { NextApiRequest, NextApiResponse } from "next";
import { token, publicText, defaultPolicy, assertAllowed, redact } from "typesecure";

const policy = defaultPolicy();

export default function handler(
  req: NextApiRequest,
  res: NextApiResponse,
) {
  if (req.method === "POST") {
    const { email, password } = req.body;

    // In a real app, verify credentials
    const sessionToken = token("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...");

    try {
      // Token can be sent over network
      assertAllowed(policy, "network", { token: sessionToken });
      const response = {
        message: publicText("Login successful"),
        token: sessionToken,
      };
      const redactedResponse = redact(response);
      res.status(200).json(redactedResponse);
    } catch (error) {
      res.status(403).json({ error: "Policy violation" });
    }
  } else {
    res.status(405).json({ error: "Method not allowed" });
  }
}
*/

export {};
