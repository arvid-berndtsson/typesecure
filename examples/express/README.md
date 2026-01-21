# Express Integration Example

This example demonstrates how to use typesecure with Express.js.

## Features

- **Middleware**: Automatic request/response sanitization
- **Authorization**: Automatic token classification from Authorization header
- **Safe Logging**: Redacted request/response logging
- **Policy Enforcement**: Validates data before network operations

## Installation

```bash
npm install express @types/express typesecure
```

## Usage

### Basic Middleware

```typescript
import express from "express";
import { typesecureMiddleware } from "./middleware";

const app = express();
app.use(express.json());
app.use(typesecureMiddleware());
```

### Custom Policy

```typescript
import { createCustomPolicy } from "typesecure";

const customPolicy = {
  name: "my-policy",
  allow: {
    log: new Set(["public"]),
    network: new Set(["public", "token"]),
    storage: new Set(["public", "pii", "secret"]),
    analytics: new Set(["public"]),
  },
};

app.use(typesecureMiddleware({ policy: customPolicy }));
```

### Safe Response Helpers

The middleware adds helper methods to the response object:

```typescript
app.get("/users/:id", (req, res) => {
  // Automatically redacts and validates
  res.safeJson({
    email: piiText("user@example.com"),
    name: piiText("John Doe"),
  });

  // Safe logging
  res.safeLog("info", "User accessed", { userId: req.params.id });
});
```

## Running the Example

```bash
# Install dependencies
npm install

# Run the example server
ts-node examples/express/example.ts
```

## API Endpoints

- `POST /users` - Create user (demonstrates PII handling)
- `POST /auth/login` - Login (demonstrates token handling)
- `GET /users/:id` - Get user profile (demonstrates authenticated requests)
