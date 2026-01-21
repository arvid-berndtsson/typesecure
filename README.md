# typesecure

`typesecure` is a **classification-first security core** for TypeScript projects.

Instead of starting with crypto primitives, it starts with what actually causes most security incidents in web apps: **data leaving the boundary it should never cross** (logs, analytics, error trackers, headers, client bundles, etc).

You “type” your data as `public | pii | secret | token | credential`, and `typesecure` helps you **enforce** safe handling using TypeScript + runtime checks.

## Features

- **Classification types**: `PublicString`, `PIIString`, `SecretString`, `TokenString`, `CredentialString`.
- **Runtime validation**: Zod-backed constructors (`secretText()`, `piiText()`, ...).
- **Redaction**: `redact()` and `safeJsonStringify()` prevent secret/PII leakage.
- **Policy enforcement**: `defaultPolicy()`, `assertAllowed()`, `audit()` help block unsafe crossings.

## Good for / Use when

- **You need to stop leaks early**: preventing secrets/PII from ending up in logs, analytics, error trackers, or client bundles.
- **You want safe defaults**: making insecure behavior harder than secure behavior.
- **You want guardrails at the boundary**: before logging, emitting telemetry, making network calls, or writing to storage.

## Not a fit / Don’t use when

- **You need a full security platform** (hosted policy registry, enterprise controls). `typesecure` is a library.
- **You need production-grade crypto primitives**. Use well-reviewed, purpose-built libraries and treat crypto carefully.
- **You only want compile-time types with zero runtime behavior**. `typesecure` deliberately includes runtime checks/redaction.

## Installation

```bash
# Using npm
npm install typesecure

# Using yarn
yarn add typesecure

# Using pnpm
pnpm add typesecure
```

## Usage

### Classification-first data handling

```typescript
import {
  piiText,
  secretText,
  token,
  publicText,
  redact,
  safeJsonStringify,
  defaultPolicy,
  assertAllowed,
  policyLog,
} from 'typesecure';

const userEmail = piiText('user@example.com');
const sessionToken = token('abc.def.ghi');
const dbPassword = secretText(process.env.DB_PASSWORD ?? '');

// Redact before logging / serialization
console.log(redact({ userEmail, sessionToken, dbPassword }));
console.log(safeJsonStringify({ userEmail, sessionToken, dbPassword }, undefined, 2));

// Enforce policy before a boundary crossing
const policy = defaultPolicy();
assertAllowed(policy, 'network', { sessionToken }); // allowed
// assertAllowed(policy, 'log', { dbPassword }); // throws

// Safe logging helper with enforcement
policyLog(policy, console, 'info', publicText('login_ok'), { userEmail });
```

### Express / Next.js examples

```typescript
// Express middleware example
import { safeLoggerAdapter, defaultPolicy, assertAllowed, token } from 'typesecure';

const log = safeLoggerAdapter(console);
const policy = defaultPolicy();

app.use((req, _res, next) => {
  const auth = req.headers.authorization?.replace(/^Bearer\s+/i, '');
  if (auth) {
    const t = token(auth);
    assertAllowed(policy, 'network', { t });
    log.info({ route: req.path, auth: t }); // will be redacted
  }
  next();
});
```

## API Reference

### Classification

- `publicText(value: string): PublicString`
- `piiText(value: string): PIIString`
- `secretText(value: string): SecretString`
- `token(value: string): TokenString`
- `credential(value: string): CredentialString`
- `reveal(value): string` (intentionally explicit)

### Redaction

- `redact(value): value` (deep traversal)
- `safeJsonStringify(value): string`
- `safeLoggerAdapter(consoleLike)`

### Policy

- `defaultPolicy(): Policy`
- `assertAllowed(policy, action, data): void`
- `audit(policy, action, data): AuditEvent`
- `policyLog(policy, logger, level, ...args): void`

## Security Considerations

Security is as much about **preventing leaks** as it is about cryptographic correctness. `typesecure` focuses on preventing accidental secret/PII exposure across common boundaries.

If you need cryptography for production-grade requirements, prefer well-reviewed primitives and consult a security professional. For production applications with high security requirements, consider:

1. Consulting a security professional
2. Using specialized security libraries
3. Keeping dependencies updated
4. Implementing proper key management
5. Using hardware security modules (HSMs) for key storage when possible
6. Conducting regular security audits
7. Following the latest NIST recommendations

## Development

To contribute to this project:

1. Clone the repository
2. Install dependencies with `pnpm install`
3. Run tests with `pnpm test`
4. Build the package with `pnpm build`

This project uses TypeScript for type safety, Jest for testing, and ESLint for code quality.

## License

MIT © [Arvid Berndtsson](https://github.com/arvid-berndtsson)

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request. 