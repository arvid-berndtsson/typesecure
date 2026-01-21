# TypeSecure Default Package Plan

## Overview

This document outlines the default package setup for `typesecure`, a TypeScript library for classification-first security enforcement. The package follows standard TypeScript/Node.js package best practices with comprehensive tooling and CI/CD integration.

## Package Structure

```
typesecure/
├── src/                    # Source code
│   ├── classification.ts   # Data classification types and constructors
│   ├── policy.ts           # Policy enforcement and audit
│   ├── redaction.ts        # Redaction utilities
│   ├── index.ts            # Main entry point (exports)
│   └── global.d.ts         # Global type definitions
├── tests/                  # Test files
│   ├── classification.test.ts
│   ├── policy.test.ts
│   ├── redaction.test.ts
│   └── tsconfig.json       # Test-specific TypeScript config
├── dist/                   # Build output (generated)
├── .github/
│   └── workflows/
│       └── publish.yml      # CI/CD pipeline
├── package.json            # Package manifest
├── tsconfig.json           # TypeScript configuration
├── jest.config.js          # Jest test configuration
├── eslint.config.js        # ESLint configuration
├── .prettierrc             # Prettier configuration
└── README.md               # Package documentation
```

## Configuration Files

### package.json
- **Name**: `typesecure`
- **Version**: `0.2.0`
- **Package Manager**: `pnpm@10.6.3`
- **Node Engine**: `>=24.0.0`
- **Main Entry**: `dist/index.js` (CJS), `dist/index.mjs` (ESM)
- **Types**: `dist/index.d.ts`

**Scripts**:
- `build`: Build package with tsup (CJS + ESM + types)
- `test`: Run Jest tests
- `lint`: Run ESLint
- `format`: Format code with Prettier
- `prepublishOnly`: Runs lint, test, and build before publishing

**Dependencies**:
- `zod`: ^3.25.76 (runtime validation)

**Dev Dependencies**:
- TypeScript tooling (tsup, ts-jest, ts-node)
- Testing (jest, @types/jest)
- Linting (eslint, @typescript-eslint/*)
- Formatting (prettier)

### TypeScript Configuration (tsconfig.json)
- **Target**: ES2022
- **Module**: CommonJS
- **Strict Mode**: Enabled
- **Declaration**: Enabled (generates .d.ts files)
- **Module Resolution**: Node

### Build Configuration
- **Tool**: `tsup`
- **Formats**: CJS (`dist/index.js`) + ESM (`dist/index.mjs`)
- **Type Definitions**: Generated automatically
- **Entry Point**: `src/index.ts`

### Test Configuration (jest.config.js)
- **Preset**: `ts-jest`
- **Environment**: Node.js
- **Test Pattern**: `**/*.test.ts`, `**/__tests__/**/*.ts`
- **Coverage**: Configured but thresholds set to 0 (no enforcement)
- **Setup**: `jest.setup.ts`

### Linting Configuration (eslint.config.js)
- **Base**: ESLint recommended + TypeScript ESLint
- **Rules**:
  - Explicit function return types required
  - No `any` types
  - Strict unsafe operations checks
  - Prettier integration
- **Test Files**: Relaxed rules (no-unsafe-* disabled)

## Core Features

### 1. Classification System
- **Types**: `PublicString`, `PIIString`, `SecretString`, `TokenString`, `CredentialString`
- **Constructors**: `publicText()`, `piiText()`, `secretText()`, `token()`, `credential()`
- **Validation**: Zod-backed runtime validation
- **Reveal**: Explicit `reveal()` function to extract underlying values

### 2. Redaction System
- **Deep Traversal**: Recursively redacts classified data
- **Key Guessing**: Redacts suspicious keys (password, apiKey, etc.)
- **Safe Serialization**: `safeJsonStringify()` for JSON output
- **Logger Adapter**: `safeLoggerAdapter()` for console-like loggers

### 3. Policy Enforcement
- **Default Policy**: Pre-configured security policy
- **Actions**: `log`, `network`, `storage`, `analytics`
- **Enforcement**: `assertAllowed()` throws on policy violations
- **Audit**: `audit()` returns decision without throwing
- **Policy Logging**: `policyLog()` combines enforcement + redaction

## Development Workflow

### Setup
```bash
pnpm install
```

### Development
```bash
pnpm run dev        # Watch mode build
pnpm run test:watch # Watch mode tests
```

### Quality Checks
```bash
pnpm run lint       # Check code quality
pnpm run lint:fix   # Auto-fix linting issues
pnpm run format     # Format code
pnpm run test       # Run tests
pnpm run test:coverage # Run tests with coverage
```

### Build
```bash
pnpm run build      # Build for production
```

### Pre-Publish Checklist
1. ✅ All tests pass (`pnpm test`)
2. ✅ Linting passes (`pnpm lint`)
3. ✅ Build succeeds (`pnpm build`)
4. ✅ Version updated in `package.json`
5. ✅ CHANGELOG updated (if applicable)
6. ✅ README reflects current API

## CI/CD Pipeline

### GitHub Actions Workflow (`.github/workflows/publish.yml`)

**Triggers**:
- Release creation (automatic)
- Manual workflow dispatch

**Steps**:
1. Checkout code
2. Setup Node.js 24
3. Setup pnpm 10.6.3
4. Install dependencies
5. Run linter
6. Run tests
7. Build package
8. Determine version (from release tag or input)
9. Publish to npm (OIDC trusted publishing)
10. Create git tag and push (if manual dispatch)

**Permissions**:
- `contents: write` (for git operations)
- `id-token: write` (for OIDC npm publishing)

## Publishing Process

### Automatic (via Release)
1. Create a GitHub release with tag (e.g., `v0.2.0`)
2. Workflow automatically:
   - Extracts version from tag
   - Runs quality checks
   - Builds package
   - Publishes to npm

### Manual (via Workflow Dispatch)
1. Go to Actions → "Publish to npm"
2. Click "Run workflow"
3. Enter version (patch/minor/major or specific version)
4. Workflow will:
   - Calculate version if needed
   - Run quality checks
   - Build package
   - Publish to npm
   - Create git tag and push

## Testing Strategy

### Test Files
- `classification.test.ts`: Tests classification constructors and type guards
- `policy.test.ts`: Tests policy enforcement and audit
- `redaction.test.ts`: Tests redaction and safe serialization

### Test Coverage
- All core functionality is tested
- Tests use Jest with ts-jest
- Coverage reporting configured but not enforced

## Code Quality

### TypeScript
- Strict mode enabled
- Explicit return types required
- No `any` types allowed (except in tests)
- Unsafe operations are errors

### Linting
- ESLint with TypeScript plugin
- Prettier integration
- Consistent code style enforced

### Best Practices
- Immutable data structures (Readonly types)
- Symbol-based type branding for classified data
- Deep traversal with cycle detection
- WeakSet/WeakMap for memory efficiency

## Package Distribution

### Build Output
- **CommonJS**: `dist/index.js`
- **ESM**: `dist/index.mjs`
- **Type Definitions**: `dist/index.d.ts`, `dist/index.d.mts`

### Published Files
Only `dist/` directory is published (configured in `package.json` `files` field).

### Entry Points
- **Main**: `dist/index.js` (CommonJS)
- **Module**: `dist/index.mjs` (ESM)
- **Types**: `dist/index.d.ts`

## Maintenance

### Dependencies
- Keep dependencies up to date
- Use `pnpm update` regularly
- Check for security vulnerabilities: `pnpm audit`

### Versioning
- Follow semantic versioning (semver)
- Update version in `package.json`
- Create git tag: `v<version>`

### Documentation
- Keep README.md up to date
- Document API changes
- Include usage examples

## Status

✅ **Package Setup Complete**
- All configuration files in place
- Tests passing (9 tests, 3 suites)
- Build working (CJS + ESM + types)
- Linting passing
- CI/CD configured
- Ready for development and publishing

## Next Steps

1. Continue feature development
2. Add more test coverage if needed
3. Update documentation as API evolves
4. Monitor and update dependencies
5. Follow semantic versioning for releases
