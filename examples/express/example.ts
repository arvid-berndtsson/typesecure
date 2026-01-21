/**
 * Example Express application using typesecure middleware.
 *
 * Run with:
 * ```bash
 * npm install express @types/express
 * ts-node examples/express/example.ts
 * ```
 */

import express, { type Request, type Response } from "express";
import {
  typesecureMiddleware,
  logRequest,
} from "./middleware";
import {
  piiText,
  publicText,
  token,
  defaultPolicy,
  assertAllowed,
  type Policy,
} from "typesecure";

const app = express();
const policy = defaultPolicy();

// Apply typesecure middleware
app.use(express.json());
app.use(typesecureMiddleware({ policy }));

// Example: User registration endpoint
app.post("/users", (req: Request, res: Response) => {
  logRequest(req, policy);

  // In a real app, you'd validate and process the request
  const { email, name } = req.body;

  // Classify user data
  const userEmail = piiText(email);
  const userName = piiText(name);

  // Store user (policy allows PII in storage)
  assertAllowed(policy, "storage", { email: userEmail, name: userName });

  // Return response (PII will be redacted by middleware)
  res.safeJson({
    message: publicText("User created successfully"),
    userId: 123,
    email: userEmail, // Will be redacted in response
  });
});

// Example: Login endpoint
app.post("/auth/login", (req: Request, res: Response) => {
  const { email, password } = req.body;

  // In a real app, you'd verify credentials
  // For demo, just return a token
  const sessionToken = token("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...");

  // Token can be sent over network (allowed by default policy)
  assertAllowed(policy, "network", { token: sessionToken });

  res.safeJson({
    message: publicText("Login successful"),
    token: sessionToken, // Will be redacted in response
  });
});

// Example: Get user profile
app.get("/users/:id", (req: Request, res: Response) => {
  // Access classified token from middleware if available
  const classifiedToken = (req as Request & {
    typesecureToken?: import("typesecure").TokenString;
  }).typesecureToken;

  if (classifiedToken) {
    // Token is already validated by middleware
    res.safeLog("info", "Authenticated request", {
      userId: req.params.id,
      token: classifiedToken,
    });
  }

  // Return user data (PII will be redacted)
  res.safeJson({
    id: req.params.id,
    email: piiText("user@example.com"),
    name: piiText("John Doe"),
  });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
  console.log("Try:");
  console.log(`  curl -X POST http://localhost:${PORT}/users -H "Content-Type: application/json" -d '{"email":"user@example.com","name":"John"}'`);
});
