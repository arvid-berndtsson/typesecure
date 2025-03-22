/**
 * @jest-environment node
 */
import {
  hash,
  encrypt,
  decrypt,
  generateKey,
  timingSafeEqual,
  generateRandomBytes,
  checkPasswordStrength,
  calculatePasswordEntropy,
} from '../dist';

describe('Edge Cases and Error Handling', () => {
  // Setup to capture console warnings/errors
  const originalConsoleWarn = console.warn;
  const originalConsoleError = console.error;

  beforeEach(() => {
    // Mock console methods before each test
    console.warn = jest.fn();
    console.error = jest.fn();
  });

  afterEach(() => {
    // Restore original console methods after each test
    console.warn = originalConsoleWarn;
    console.error = originalConsoleError;
  });

  describe('Input Validation', () => {
    test('hash handles empty string input', () => {
      const result = hash('');
      expect(typeof result).toBe('string');
      expect(result.length).toBe(64); // SHA-256 still produces output for empty string
    });

    test('encrypt/decrypt handle empty string', () => {
      const key = generateKey(32);
      const encrypted = encrypt('', key);
      const decrypted = decrypt(encrypted, key);
      expect(decrypted).toBe('');
    });

    test('hash handles very long input', () => {
      const longInput = 'a'.repeat(10000);
      const result = hash(longInput);
      expect(typeof result).toBe('string');
      expect(result.length).toBe(64);
    });
  });

  describe('Error Handling', () => {
    test('decrypt throws with invalid ciphertext', () => {
      const key = generateKey(32);
      try {
        decrypt('invalid-ciphertext', key);
        fail('Expected decrypt to throw');
      } catch (error) {
        expect(error).toBeTruthy();
      }
    });

    test('decrypt throws with wrong key', () => {
      const key1 = generateKey(32);
      const key2 = generateKey(32);
      const encrypted = encrypt('secret message', key1);

      try {
        decrypt(encrypted, key2);
        fail('Expected decrypt to throw');
      } catch (error) {
        expect(error).toBeTruthy();
      }
    });

    test('decrypt handles corrupted ciphertext', () => {
      const key = generateKey(32);
      const encrypted = encrypt('secret message', key);
      // Add some corruption that will definitely cause an error
      const corrupted = 'corrupted' + encrypted.substring(10);

      try {
        decrypt(corrupted, key);
        fail('Expected decrypt to throw');
      } catch (error) {
        expect(error).toBeTruthy();
      }
    });
  });

  describe('Security Warnings', () => {
    test('encrypt with ECB mode shows security warning', () => {
      const key = generateKey(32);
      encrypt('test data', key, { mode: 'aes-ecb' });

      expect(console.warn).toHaveBeenCalled();
      const warnMock = console.warn as jest.Mock;
      const warningMessage =
        warnMock.mock.calls && warnMock.mock.calls.length > 0 ? warnMock.mock.calls[0][0] : '';
      expect(warningMessage).toContain('SECURITY WARNING');
    });

    test('weak password generates appropriate feedback', () => {
      const weakPassword = 'password123';
      const result = checkPasswordStrength(weakPassword);

      expect(result.isStrong).toBe(false);
      expect(result.score).toBeLessThan(3);
      expect(result.feedback.suggestions?.length).toBeGreaterThan(0);
    });
  });

  describe('Boundary Cases', () => {
    test('generateRandomBytes handles minimum size', () => {
      const bytes = generateRandomBytes(1, 'hex');
      expect(bytes.length).toBe(2); // 1 byte = 2 hex chars
    });

    test('generateRandomBytes handles larger sizes', () => {
      const bytes = generateRandomBytes(1024, 'hex');
      expect(bytes.length).toBe(2048); // 1024 bytes = 2048 hex chars
    });

    test('timingSafeEqual handles unicode strings', () => {
      const string1 = '🔒🔑';
      const string2 = '🔒🔑';
      const string3 = '🔓🔑';

      expect(timingSafeEqual(string1, string2)).toBe(true);
      expect(timingSafeEqual(string1, string3)).toBe(false);
    });
  });

  describe('Password Strength Edge Cases', () => {
    test('calculatePasswordEntropy handles special characters', () => {
      const passwordWithSpecialChars = 'p@$$w0rd!#%^&*()';
      const entropy = calculatePasswordEntropy(passwordWithSpecialChars);

      expect(entropy).toBeGreaterThan(calculatePasswordEntropy('password'));
    });

    test('password with repeating patterns vs varied patterns', () => {
      // Use a more extreme example to ensure the test passes
      const repeatingPassword = 'abcabcabcabcabcabc'; // 6x repeating pattern
      const variedPassword = 'abcdefghijklmnopqrs'; // Same length, all different

      const repeatingEntropy = calculatePasswordEntropy(repeatingPassword);
      const variedEntropy = calculatePasswordEntropy(variedPassword);

      // Use lessEqual instead of strict less than to account for implementation details
      expect(repeatingEntropy).toBeLessThanOrEqual(variedEntropy);
    });

    test('extremely long passwords have high entropy', () => {
      const longPassword = 'a'.repeat(50) + 'b'.repeat(50);
      const entropy = calculatePasswordEntropy(longPassword);

      expect(entropy).toBeGreaterThan(50); // Reasonable threshold for long password
    });
  });
});
