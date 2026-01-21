# Edge Function Examples

Examples for using typesecure with edge runtimes (Vercel Edge, Cloudflare Workers, etc.).

## Vercel Edge Functions

### App Router

```typescript
// app/api/hello/route.ts
import { edgeHandler } from "./examples/edge/vercel-edge";
import { publicText, piiText } from "typesecure";

export const runtime = "edge";

export const GET = edgeHandler(async (req) => {
  return Response.json({
    message: publicText("Hello from edge!"),
    email: piiText("user@example.com"), // Will be redacted
  });
});
```

## Cloudflare Workers

```typescript
// worker.ts
import { cloudflareHandler } from "./examples/edge/cloudflare-worker";
import { publicText, piiText } from "typesecure";

export default {
  async fetch(request: Request): Promise<Response> {
    return cloudflareHandler(async (req) => {
      return Response.json({
        message: publicText("Hello from Cloudflare!"),
        email: piiText("user@example.com"), // Will be redacted
      });
    })(request);
  }
};
```

## Features

- **Edge-Compatible**: Uses only browser-compatible APIs
- **Automatic Redaction**: Responses are automatically redacted
- **Policy Enforcement**: Validates data before sending
- **Token Support**: Extract and classify Authorization tokens

## Limitations

Edge functions have limited APIs compared to Node.js:
- No file system access
- No Node.js-specific modules
- Limited runtime APIs

typesecure is designed to work in these environments without Node.js-specific dependencies.
