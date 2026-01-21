# Next.js Integration Example

This example demonstrates how to use typesecure with Next.js (App Router and Pages Router).

## Features

- **Middleware**: Automatic request sanitization
- **API Route Helpers**: Safe API handlers with automatic redaction
- **Policy Enforcement**: Validates data before network operations
- **Safe Logging**: Redacted logging helpers

## Installation

```bash
npm install next typesecure
```

## App Router (Next.js 13+)

### 1. Create Middleware

Create `middleware.ts` at the root of your Next.js app:

```typescript
import { typesecureMiddleware } from "./examples/nextjs/middleware";
import { defaultPolicy } from "typesecure";

export default typesecureMiddleware({ policy: defaultPolicy() });

export const config = {
  matcher: "/api/:path*",
};
```

### 2. Create API Routes

```typescript
// app/api/users/route.ts
import { createSafeApiHandler } from "./examples/nextjs/api-helpers";
import { piiText, publicText, defaultPolicy } from "typesecure";

const policy = defaultPolicy();

export const POST = createSafeApiHandler(async (req) => {
  const body = await req.json();
  const email = piiText(body.email);

  // Response automatically redacted and validated
  return Response.json({
    message: publicText("User created"),
    email, // Will be redacted
  });
});
```

## Pages Router

### API Route Example

```typescript
// pages/api/users.ts
import type { NextApiRequest, NextApiResponse } from "next";
import { piiText, defaultPolicy, assertAllowed, redact } from "typesecure";
import { safeLog } from "./examples/nextjs/api-helpers";

const policy = defaultPolicy();

export default function handler(req: NextApiRequest, res: NextApiResponse) {
  const email = piiText(req.body.email);

  // Safe logging
  safeLog(policy, "info", "User created", { email });

  // Validate and redact response
  try {
    assertAllowed(policy, "network", { email });
    const redacted = redact({ email });
    res.status(200).json(redacted);
  } catch (error) {
    res.status(403).json({ error: "Policy violation" });
  }
}
```

## Helpers

### Safe Logging

```typescript
import { safeLog } from "./examples/nextjs/api-helpers";

safeLog(policy, "info", "User action", { email: piiText("user@example.com") });
```

### Safe Stringify

```typescript
import { safeStringify } from "./examples/nextjs/api-helpers";

const logData = safeStringify({ email: piiText("user@example.com") }, policy);
console.log(logData);
```

## Running the Example

```bash
# Install dependencies
npm install

# Run Next.js dev server
npm run dev
```

Visit:
- `http://localhost:3000/api/users` - User endpoints
- `http://localhost:3000/api/auth/login` - Login endpoint
