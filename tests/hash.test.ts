/**
 * @jest-environment node
 */
import { hash, verifyHash, generateRandomBytes, timingSafeEqual } from '../dist';

describe('Hash Utilities', () => {
  describe('hash', () => {
    it('should create a hash using the default algorithm (sha256)', () => {
      const result = hash('test');
      expect(typeof result).toBe('string');
      expect(result.length).toBe(64); // SHA-256 produces a 64-character hex string
    });

    it('should create different hashes for different inputs', () => {
      const hash1 = hash('test1');
      const hash2 = hash('test2');
      expect(hash1).not.toBe(hash2);
    });

    it('should support different algorithms', () => {
      const md5Hash = hash('test', { algorithm: 'md5' });
      const sha1Hash = hash('test', { algorithm: 'sha1' });
      const sha256Hash = hash('test', { algorithm: 'sha256' });

      expect(md5Hash.length).toBe(32); // MD5 produces a 32-character hex string
      expect(sha1Hash.length).toBe(40); // SHA-1 produces a 40-character hex string
      expect(sha256Hash.length).toBe(64); // SHA-256 produces a 64-character hex string
    });
  });

  describe('verifyHash', () => {
    it('should verify a hash correctly', () => {
      const testString = 'test-string';
      const hashedValue = hash(testString);

      expect(verifyHash(testString, hashedValue)).toBe(true);
      expect(verifyHash('wrong-string', hashedValue)).toBe(false);
    });
  });

  describe('timingSafeEqual', () => {
    it('should return true for equal strings', () => {
      expect(timingSafeEqual('secret-token', 'secret-token')).toBe(true);
    });

    it('should return false for unequal strings', () => {
      expect(timingSafeEqual('secret-token', 'different-token')).toBe(false);
    });

    it('should return false for strings of different lengths', () => {
      expect(timingSafeEqual('short', 'longer-string')).toBe(false);
    });
  });

  describe('generateRandomBytes', () => {
    it('should generate random bytes of specified length in hex format', () => {
      const random16 = generateRandomBytes(16, 'hex');
      expect(typeof random16).toBe('string');
      expect(random16.length).toBe(32); // 16 bytes = 32 hex characters
    });

    it('should generate random bytes in base64 format', () => {
      const random16 = generateRandomBytes(16, 'base64');
      expect(typeof random16).toBe('string');
      // Base64 encoding: 4 characters per 3 bytes, with padding
      expect(random16.length).toBeGreaterThanOrEqual(Math.ceil((16 * 4) / 3));
    });

    it('should generate different values on each call', () => {
      const random1 = generateRandomBytes(16);
      const random2 = generateRandomBytes(16);
      expect(random1).not.toBe(random2);
    });
  });
});
