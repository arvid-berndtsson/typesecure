# typesecure

`typesecure` is a **classification-first security core** for TypeScript projects.

Instead of starting with crypto primitives, it starts with what actually causes most security incidents in web apps: **data leaving the boundary it should never cross** (logs, analytics, error trackers, headers, client bundles, etc).

You “type” your data as `public | pii | secret | token | credential`, and `typesecure` helps you **enforce** safe handling using TypeScript + runtime checks.

## Features

- **Classification types**: `PublicString`, `PIIString`, `SecretString`, `TokenString`, `CredentialString`.
- **Runtime validation**: Zod-backed constructors (`secretText()`, `piiText()`, ...).
- **Redaction**: `redact()` and `safeJsonStringify()` prevent secret/PII leakage.
- **Policy enforcement**: `defaultPolicy()`, `assertAllowed()`, `audit()` help block unsafe crossings.
- **Classification and scanning**: `classifyDeep()`, `scanText()`, `scanFile()`, `scanDirectory()` for logs/files.
- **CLI scanning**: `typesecure scan` with baseline diff, CI exit codes, and autofix modes.

## Good for / Use when

- **You need to stop leaks early**: preventing secrets/PII from ending up in logs, analytics, error trackers, or client bundles.
- **You want safe defaults**: making insecure behavior harder than secure behavior.
- **You want guardrails at the boundary**: before logging, emitting telemetry, making network calls, or writing to storage.

## Not a fit / Don’t use when

- **You need a full security platform** (hosted policy registry, enterprise controls). `typesecure` is a library.
- **You need production-grade crypto primitives**. Use well-reviewed, purpose-built libraries and treat crypto carefully.
- **You only want compile-time types with zero runtime behavior**. `typesecure` deliberately includes runtime checks/redaction.

## Installation

Requires Node.js `>=18.18.0`.

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
} from "typesecure";

const userEmail = piiText("user@example.com");
const sessionToken = token("abc.def.ghi");
const dbPassword = secretText(process.env.DB_PASSWORD ?? "");

// Redact before logging / serialization
console.log(redact({ userEmail, sessionToken, dbPassword }));
console.log(
  safeJsonStringify({ userEmail, sessionToken, dbPassword }, undefined, 2),
);

// Enforce policy before a boundary crossing
const policy = defaultPolicy();
assertAllowed(policy, "network", { sessionToken }); // allowed
// assertAllowed(policy, 'log', { dbPassword }); // throws

// Safe logging helper with enforcement
policyLog(policy, console, "info", publicText("login_ok"), { userEmail });
```

### Express / Next.js examples

```typescript
// Express middleware example
import {
  safeLoggerAdapter,
  defaultPolicy,
  assertAllowed,
  token,
} from "typesecure";

const log = safeLoggerAdapter(console);
const policy = defaultPolicy();

app.use((req, _res, next) => {
  const auth = req.headers.authorization?.replace(/^Bearer\s+/i, "");
  if (auth) {
    const t = token(auth);
    assertAllowed(policy, "network", { t });
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
- `redactText(value): string` (mask sensitive fragments in plain text)
- `detectText(value): StringDetection[]` (return ranges/kinds for audit workflows)
- `safeJsonStringify(value): string`
- `safeLoggerAdapter(consoleLike)`
- Redaction options:
  - `guessByKey` (default `true`): redact suspicious keys like `password`, `token`, `apiKey`.
  - `guessByValue` (default `true`): auto-detect and redact sensitive-looking values.
  - `useDefaultValueDetector` (default `true`): keep built-in rule-based detectors on/off.
  - `stringDetectors`: add custom detectors (for NER/ML or domain-specific logic).
  - `minDetectionConfidence` (default `0`): ignore low-confidence custom detections.
- Value detection masks only the sensitive fragments inside a larger string (instead of replacing the whole text), including:
  - PII: email, phone, SSN, date of birth (`YYYY-MM-DD`), IPv4 address, payment card numbers (Luhn-validated).
  - Secrets/tokens: JWTs, private key PEM blocks, GitHub tokens, AWS access keys, Stripe secret keys, OpenAI-style `sk-...` keys, credential pairs (`user:pass`), high-entropy token-like strings.

Example custom detector (NER/ML-style integration):

```typescript
const out = redact(
  { text: "Customer Jane Doe uses jane@example.com" },
  {
    stringDetectors: [
      (value) => {
        const name = "Jane Doe";
        const idx = value.indexOf(name);
        return idx >= 0
          ? [{ start: idx, end: idx + name.length, kind: "pii", confidence: 0.92, source: "ml.ner" }]
          : [];
      },
    ],
    minDetectionConfidence: 0.8,
  },
);
```

### Policy

- `defaultPolicy(): Policy`
- `assertAllowed(policy, action, data): void`
- `audit(policy, action, data): AuditEvent`
- `policyLog(policy, logger, level, ...args): void`

### Classification & Scanning

- `classifyDeep(value, options)` returns structured findings with path/kind/confidence/source.
- `scanText(value, options)` scans plain text and returns findings plus redacted text.
- `scanFile(filePath, options)` scans one file with optional fix mode.
- `scanDirectory(paths, options)` scans recursively with extension filters, baseline diff, and block findings.
- `createBaseline(findings)`, `serializeBaseline(...)`, `parseBaseline(...)`, `applyBaselineDiff(...)`.

Detector packs:

- `all` / `core`: full default detection set
- `compliance`: PII + credential-oriented detections
- `cloud-keys`: cloud token/secret detectors (AWS/GitHub/Stripe/OpenAI/private keys/JWT/high-entropy)

Confidence workflow:

- `high`: block (for configured blocked kinds)
- `medium`: review
- `low`: info

### CLI

```bash
# scan current directory
typesecure scan .

# CI mode (exit 1 on blocking findings)
typesecure scan . --ci

# write baseline and later show only new findings
typesecure scan . --write-baseline .typesecure-baseline.json
typesecure scan . --baseline .typesecure-baseline.json --new-only

# sanitize files without editing originals
typesecure scan ./logs --fix-out-dir ./sanitized-logs
```

### Observability (Azure-ready)

- `defaultTelemetryConfig(environment)`
- `telemetryConfigFromEnv(process.env)`
- `createTelemetryRecorder(config, options)`
- `createAzureApplicationInsightsSink(client, { dryRun, onEmit })`
- `assessAzureReadiness(input)`
- `buildIncidentForensicsSummary(events)`
- `detectTelemetryAlerts(events, rules)`

Example App Insights integration:

```typescript
import appInsights from "applicationinsights";
import {
  createAzureApplicationInsightsSink,
  createTelemetryRecorder,
  telemetryConfigFromEnv,
} from "typesecure";

appInsights
  .setup(process.env.APPLICATIONINSIGHTS_CONNECTION_STRING)
  .start();

const aiSink = createAzureApplicationInsightsSink(
  appInsights.defaultClient,
);
const recorder = createTelemetryRecorder(telemetryConfigFromEnv(process.env), {
  auditSinks: [aiSink],
  logSinks: [aiSink],
});
```

For zero-cost verification (no network writes), use dry run:

```typescript
const aiSink = createAzureApplicationInsightsSink(appInsights.defaultClient, {
  dryRun: true,
  onEmit: (envelope) => {
    console.log(envelope.name);
  },
});
```

Local smoke test (no Azure spend):

```bash
pnpm test:smoke:observability
```

You can also test attack reconstruction and local detections fully offline through Jest:

```bash
pnpm test
```

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
5. Run Enron dataset integration tests with `pnpm test:data`

### Optional: external dataset setup

For larger redaction/policy experiments (Enron + Synthea FHIR), fetch datasets locally:

```bash
pnpm data:setup
```

This command downloads and extracts to:

- `data/enron-maildir`
- `data/synthea_sample_data_fhir_latest`

Notes:

- `data/` is gitignored and not published to npm.
- `pnpm test` excludes dataset suites by default.
- `pnpm test:data` runs Enron dataset tests with verbose output.
- `pnpm test:data:synthea` runs Synthea-specific dataset tests.
- `pnpm test:data:all` runs all dataset suites.
- You can override source URLs with `ENRON_URL=...` and/or `SYNTHEA_FHIR_URL=...`.
- You can change destination with `DATA_DIR=/path/to/data`.

Dataset sources:

- Enron: [https://www.cs.cmu.edu/~enron/](https://www.cs.cmu.edu/~enron/)
- Synthea: [https://github.com/synthetichealth/synthea-sample-data/](https://github.com/synthetichealth/synthea-sample-data/)

This project uses TypeScript for type safety, Jest for testing, and ESLint for code quality.

## Dataset Acknowledgements

We use these public datasets for redaction and policy testing:

- [CMU Enron Email Dataset](https://www.cs.cmu.edu/~enron/)
- [Synthea Sample Data](https://github.com/synthetichealth/synthea-sample-data/)

Personal note: I am especially interested in the historical context around Enron, including how it was able to happen and the improvements in governance and controls that followed.

## License

MIT © [Arvid Berndtsson](https://github.com/arvid-berndtsson)

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
