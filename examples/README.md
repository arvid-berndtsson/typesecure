# typesecure Examples

This directory contains examples and integrations for using typesecure with various frameworks and runtimes.

## Examples

### Express.js
- **Location**: `express/`
- **Features**: Middleware for request/response sanitization, safe logging helpers
- **See**: [Express README](./express/README.md)

### Next.js
- **Location**: `nextjs/`
- **Features**: App Router and Pages Router examples, middleware, API route helpers
- **See**: [Next.js README](./nextjs/README.md)

### NestJS
- **Location**: `nestjs/`
- **Features**: Interceptors, decorators, DTO classification
- **See**: [NestJS README](./nestjs/README.md)

### Edge Functions
- **Location**: `edge/`
- **Features**: Vercel Edge and Cloudflare Workers examples
- **See**: [Edge README](./edge/README.md)

## Quick Start

Each example directory contains:
- Implementation code
- Usage examples
- README with detailed instructions

## Common Patterns

### Classification

```typescript
import { piiText, secretText, token } from "typesecure";

const email = piiText("user@example.com");
const password = secretText("secret123");
const jwt = token("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...");
```

### Policy Enforcement

```typescript
import { defaultPolicy, assertAllowed } from "typesecure";

const policy = defaultPolicy();
assertAllowed(policy, "log", { email: piiText("user@example.com") }); // Throws
assertAllowed(policy, "storage", { email: piiText("user@example.com") }); // OK
```

### Redaction

```typescript
import { redact, safeJsonStringify } from "typesecure";

const data = { email: piiText("user@example.com") };
const redacted = redact(data);
// { email: "[REDACTED:pii]" }

const json = safeJsonStringify(data);
// '{"email":"[REDACTED:pii]"}'
```

## Contributing

If you'd like to add an example for another framework, please:
1. Create a new directory under `examples/`
2. Include implementation code and examples
3. Add a README with usage instructions
4. Follow the existing patterns
