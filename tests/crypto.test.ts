import {
  hash,
  verifyHash,
  encrypt,
  decrypt,
  encryptJson,
  decryptJson,
  generateKey,
  hashPassword,
  verifyPassword,
  timingSafeEqual,
  generateRandomBytes,
  checkPasswordStrength,
  generateSecurePassword,
  calculatePasswordEntropy,
  getSecurityLevel,
  SecurityLevel,
} from '../dist';

// Remove Jest globals import
// import { describe, test, expect, beforeEach } from '@jest/globals';

describe('Password Utilities', () => {
  // Setup to capture console warnings/errors
  const originalConsoleWarn = console.warn;

  beforeEach(() => {
    // Mock console methods before each test
    console.warn = jest.fn();
  });

  afterEach(() => {
    // Restore original console methods after each test
    console.warn = originalConsoleWarn;
  });

  test('should generate secure password', () => {
    const password = generateSecurePassword({ minimumPasswordLength: 16 });
    expect(password.length).toBeGreaterThanOrEqual(16);

    const strength = checkPasswordStrength(password);
    expect(strength.score).toBeGreaterThanOrEqual(3);
    expect(strength.isStrong).toBe(true);
  });

  test('should calculate password entropy', () => {
    const samplePasswords = [
      'password123',
      'P@ssw0rd!',
      'qwerty12345',
      '1234567890',
      'ThisIsALongPasswordButSimple',
      'Tr0ub4dor&3',
      'correct horse battery staple',
    ];

    samplePasswords.forEach(pwd => {
      const entropy = calculatePasswordEntropy(pwd);
      expect(entropy).toBeGreaterThan(0);

      const strengthResult = checkPasswordStrength(pwd);
      expect(typeof strengthResult.score).toBe('number');
      expect(typeof strengthResult.isStrong).toBe('boolean');
    });
  });
});

describe('Secure Password Hashing', () => {
  test('should hash and verify password', () => {
    const pwdToHash = 'MySecurePassword123!';
    const hashedPwd = hashPassword(pwdToHash, {
      algorithm: 'pbkdf2',
      iterations: 10000,
    });

    expect(hashedPwd.hash).toBeTruthy();
    expect(hashedPwd.salt).toBeTruthy();
    expect(hashedPwd.params).toBeTruthy();

    const isVerified = verifyPassword(pwdToHash, hashedPwd.hash, hashedPwd.salt, hashedPwd.params);
    expect(isVerified).toBeTruthy();
    expect(verifyPassword('incorrect-password', hashedPwd.hash, hashedPwd.salt, hashedPwd.params)).toBe(
      false
    );
  });

  test('supports base64 salt encoding', () => {
    const password = 'AnotherSecurePassword!123';
    const hashedPwd = hashPassword(password, {
      saltEncoding: 'base64',
      saltLength: 48,
      iterations: 12000,
    });

    expect(hashedPwd.salt).toMatch(/^[A-Za-z0-9+/=]+$/);
    const isVerified = verifyPassword(password, hashedPwd.hash, hashedPwd.salt, hashedPwd.params);
    expect(isVerified).toBe(true);
  });

  test('timing-safe comparison works correctly', () => {
    expect(timingSafeEqual('secret-token', 'secret-token')).toBe(true);
    expect(timingSafeEqual('secret-token', 'another-token')).toBe(false);
  });
});

describe('Hashing', () => {
  test('should hash and verify data', () => {
    const data = 'test data';
    const hashedValue = hash(data, { algorithm: 'sha256', encoding: 'hex' });

    expect(hashedValue).toBeTruthy();
    expect(typeof hashedValue).toBe('string');

    const verified = verifyHash(data, hashedValue, { algorithm: 'sha256', encoding: 'hex' });
    expect(verified).toBe(true);
  });
});

describe('Random Bytes', () => {
  test('should generate random bytes', () => {
    const hexBytes = generateRandomBytes(16, 'hex');
    expect(hexBytes).toHaveLength(32); // 16 bytes = 32 hex chars

    const base64Bytes = generateRandomBytes(16, 'base64');
    expect(base64Bytes).toBeTruthy();
    expect(typeof base64Bytes).toBe('string');
  });
});

describe('Encryption', () => {
  let key: string;

  beforeEach(() => {
    key = generateKey(32);
  });

  test('should encrypt and decrypt with CBC mode', () => {
    const plaintext = 'Secret information with CBC mode';
    const encryptedCBC = encrypt(plaintext, key, { mode: 'aes-cbc' });

    expect(encryptedCBC).toBeTruthy();
    expect(typeof encryptedCBC).toBe('string');

    const decrypted = decrypt(encryptedCBC, key, { mode: 'aes-cbc' });
    expect(decrypted).toBe(plaintext);
  });

  test('should encrypt and decrypt with GCM mode', () => {
    const plaintext = 'Secret information with GCM mode';
    const aad = 'Associated data for authentication';

    const encryptedGCM = encrypt(plaintext, key, {
      mode: 'aes-gcm',
      aad,
    });

    expect(encryptedGCM).toBeTruthy();

    const decrypted = decrypt(encryptedGCM, key, {
      mode: 'aes-gcm',
      aad,
    });

    expect(decrypted).toBe(plaintext);
  });

  test('should encrypt and decrypt with ECB mode', () => {
    // Save and mock console.warn just for this specific test
    const originalConsoleWarn = console.warn;
    console.warn = jest.fn();

    try {
      const plaintext = 'Secret information with ECB mode';
      const encryptedECB = encrypt(plaintext, key, { mode: 'aes-ecb' });

      expect(encryptedECB).toBeTruthy();

      const decrypted = decrypt(encryptedECB, key, { mode: 'aes-ecb' });
      expect(decrypted).toBe(plaintext);

      // Verify that warnings were shown
      const warnMock = console.warn as jest.Mock;
      expect(warnMock).toHaveBeenCalled();
    } finally {
      // Restore console.warn
      console.warn = originalConsoleWarn;
    }
  });

  test('should encrypt and decrypt structured JSON payloads', () => {
    const payload = {
      userId: 'user-123',
      scopes: ['read', 'write'],
      metadata: { issuedAt: Date.now() },
    };

    const encryptedPayload = encryptJson(payload, key, { mode: 'aes-gcm' });
    expect(typeof encryptedPayload).toBe('string');

    const decryptedPayload = decryptJson<typeof payload>(encryptedPayload, key, { mode: 'aes-gcm' });
    expect(decryptedPayload).toEqual(payload);
  });
});

describe('Security Level Assessment', () => {
  test('should correctly assess security levels', () => {
    const securityLevels = [
      { mode: 'aes-gcm' as const, padding: 'Pkcs7' as const, expected: SecurityLevel.HIGH },
      { mode: 'aes-cbc' as const, padding: 'Pkcs7' as const, expected: SecurityLevel.HIGH },
      { mode: 'aes-ctr' as const, padding: 'Pkcs7' as const, expected: SecurityLevel.HIGH },
      { mode: 'aes-ecb' as const, padding: 'Pkcs7' as const, expected: SecurityLevel.INSECURE },
    ];

    securityLevels.forEach(({ mode, padding, expected }) => {
      const level = getSecurityLevel({ mode, padding });
      expect(level).toBe(expected);
    });
  });
});
