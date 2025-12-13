# typesecure

A focused TypeScript cryptography package that provides secure encryption and hashing utilities with strong typing and runtime validation using Zod.

## Features

- 🔐 **Strong Typing**: Built with TypeScript for complete type safety.
- ✅ **Runtime Validation**: Uses Zod to validate inputs and ensure security.
- 🔍 **Advanced Encryption**: AES encryption with multiple modes (CBC, CTR, GCM, ECB).
- 🛡️ **Authenticated Encryption**: GCM mode for authenticated encryption with additional data (AAD).
- 🔏 **Cryptographic Hashing**: SHA-256, SHA-512, SHA-3, and more.
- 📝 **HMAC Signatures**: Create and verify message authentication codes.
- ⏱️ **Timing-Safe Comparison**: Prevent timing attacks with constant-time string comparison.
- 🚦 **Security Level Assessment**: Analyze and report the security level of encryption configurations.
- 🔑 **Password Hashing**: PBKDF2 for secure password hashing with salt and configurable iterations.
- 📦 **JSON Payload Encryption**: Helpers to safely encrypt and decrypt structured data.

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

### Encryption with Security Assessment

```typescript
import { encrypt, decrypt, encryptJson, decryptJson, generateKey, getSecurityLevel, SecurityLevel } from 'typesecure';

// Generate a secure key
const key = generateKey();

// Encrypt data with GCM (authenticated encryption)
const encrypted = encrypt('Sensitive information', key, {
  mode: 'aes-gcm',
  aad: 'Additional authenticated data' // Optional
});

// Decrypt data
const decrypted = decrypt(encrypted, key, {
  mode: 'aes-gcm',
  aad: 'Additional authenticated data' // Must match encryption
});

// Assess security level of encryption options
const securityLevel = getSecurityLevel({ mode: 'aes-cbc', padding: 'Pkcs7' });
if (securityLevel === SecurityLevel.HIGH) {
  console.log('Using high security encryption configuration');
}

// Encrypt structured JSON payloads end-to-end
const payload = {
  userId: 'user-123',
  scopes: ['read', 'write'],
  metadata: { issuedAt: Date.now() },
};

const encryptedPayload = encryptJson(payload, key, { mode: 'aes-gcm', aad: 'session' });
const decryptedPayload = decryptJson<typeof payload>(encryptedPayload, key, { mode: 'aes-gcm', aad: 'session' });
console.log(decryptedPayload);
```

### Secure Password Storage

```typescript
import { hashPassword, verifyPassword } from 'typesecure';

// Hash a password with PBKDF2
const { hash, salt, params } = hashPassword('userPassword123', {
  algorithm: 'pbkdf2',
  iterations: 10000,
  saltLength: 32,
  keyLength: 64,
  saltEncoding: 'base64' // Optional: choose 'hex' (default) or 'base64'
});

// Store hash, salt, and params in your database

// Later, verify the password
const isValid = verifyPassword('userPassword123', hash, salt, params);
const isInvalid = verifyPassword('wrong password', hash, salt, params);
```

### Timing-Safe Comparison and Random Bytes Generation

```typescript
import { timingSafeEqual, generateRandomBytes } from 'typesecure';

// Compare strings in constant time to prevent timing attacks
const isEqual = timingSafeEqual(userProvidedToken, storedToken);

// Generate cryptographically secure random bytes
const randomBytes = generateRandomBytes(32, 'hex');
```

### Hashing and HMAC

```typescript
import { hash, verifyHash, hmac } from 'typesecure';

// Create a hash
const hashedValue = hash('data to hash', {
  algorithm: 'sha256',
  encoding: 'hex'
});

// Verify a hash
const isMatch = verifyHash('data to hash', hashedValue, {
  algorithm: 'sha256',
  encoding: 'hex'
});

// Create an HMAC
const signature = hmac('message', 'secret key', {
  algorithm: 'sha256',
  encoding: 'base64'
});
```

## API Reference

### Encryption

- `encrypt(text: string, key: string, options?: Partial<EncryptionOptions>): string`
- `decrypt(encryptedText: string, key: string, options?: Partial<EncryptionOptions>): string`
- `encryptJson<T>(payload: T, key: string, options?: Partial<EncryptionOptions>): string`
- `decryptJson<T>(encryptedPayload: string, key: string, options?: Partial<EncryptionOptions>): T`
- `generateKey(length?: number): string`
- `getSecurityLevel(options: EncryptionOptions): SecurityLevel`

### Secure Password Storage

- `hashPassword(password: string, options?: Partial<PasswordHashOptions>): { hash: string; salt: string; params: PasswordHashOptions }`
- `verifyPassword(password: string, hash: string, salt: string, options?: Partial<PasswordHashOptions>): boolean`
- `timingSafeEqual(a: string, b: string, options?: Partial<TimingSafeOptions>): boolean`
- `generateRandomBytes(length?: number, encoding?: 'hex' | 'base64'): string`

`PasswordHashOptions` now include a `saltEncoding` field (`'hex'` by default) so you can store salts in the format that best matches your persistence strategy.

### Hashing

- `hash(input: string, options?: Partial<HashOptions>): string`
- `verifyHash(input: string, hashedValue: string, options?: Partial<HashOptions>): boolean`
- `hmac(input: string, key: string, options?: Partial<HashOptions>): string`

## Security Considerations

This package implements best practices for cryptographic operations, but remember that cryptography is complex. For production applications with high security requirements, consider:

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