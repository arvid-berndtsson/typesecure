import CryptoJS from 'crypto-js';
import {
  HashOptions,
  HashOptionsSchema,
  PasswordHashOptions,
  PasswordHashOptionsSchema,
  TimingSafeOptions,
  TimingSafeOptionsSchema,
} from '../types';

/**
 * Creates a hash of the input string using the specified algorithm
 * @param input - The string to hash
 * @param options - Hash options
 * @returns The hashed string
 */
export function hash(input: string, options?: Partial<HashOptions>): string {
  const validatedOptions = HashOptionsSchema.parse({
    algorithm: options?.algorithm || 'sha256',
    encoding: options?.encoding || 'hex',
  });

  let hashedValue: CryptoJS.lib.WordArray;

  switch (validatedOptions.algorithm) {
    case 'md5':
      hashedValue = CryptoJS.MD5(input);
      break;
    case 'sha1':
      hashedValue = CryptoJS.SHA1(input);
      break;
    case 'sha256':
      hashedValue = CryptoJS.SHA256(input);
      break;
    case 'sha512':
      hashedValue = CryptoJS.SHA512(input);
      break;
    case 'sha3':
      hashedValue = CryptoJS.SHA3(input);
      break;
    default:
      hashedValue = CryptoJS.SHA256(input);
  }

  return validatedOptions.encoding === 'base64'
    ? hashedValue.toString(CryptoJS.enc.Base64)
    : hashedValue.toString(CryptoJS.enc.Hex);
}

/**
 * Verifies if an input matches a previously hashed value
 * @param input - The plain text to verify
 * @param hashedValue - The hashed value to compare against
 * @param options - Hash options
 * @returns True if the input matches the hash, false otherwise
 */
export function verifyHash(
  input: string,
  hashedValue: string,
  options?: Partial<HashOptions>
): boolean {
  const newHash = hash(input, options);
  return newHash === hashedValue;
}

/**
 * Creates a HMAC (Hash-based Message Authentication Code) of the input
 * @param input - The input message
 * @param key - The secret key
 * @param options - Hash options
 * @returns The HMAC signature
 */
export function hmac(input: string, key: string, options?: Partial<HashOptions>): string {
  const validatedOptions = HashOptionsSchema.parse({
    algorithm: options?.algorithm || 'sha256',
    encoding: options?.encoding || 'hex',
  });

  let hmacValue: CryptoJS.lib.WordArray;

  switch (validatedOptions.algorithm) {
    case 'md5':
      hmacValue = CryptoJS.HmacMD5(input, key);
      break;
    case 'sha1':
      hmacValue = CryptoJS.HmacSHA1(input, key);
      break;
    case 'sha256':
      hmacValue = CryptoJS.HmacSHA256(input, key);
      break;
    case 'sha512':
      hmacValue = CryptoJS.HmacSHA512(input, key);
      break;
    case 'sha3':
      hmacValue = CryptoJS.HmacSHA3(input, key);
      break;
    default:
      hmacValue = CryptoJS.HmacSHA256(input, key);
  }

  return validatedOptions.encoding === 'base64'
    ? hmacValue.toString(CryptoJS.enc.Base64)
    : hmacValue.toString(CryptoJS.enc.Hex);
}

/**
 * Performs a secure password hashing using PBKDF2 (default), Argon2, or bcrypt simulation
 * Note: This is a simplified implementation. For production, consider using a specialized library
 * @param password - The password to hash
 * @param options - Password hash options
 * @returns An object containing the hash, salt, and parameters
 */
export function hashPassword(
  password: string,
  options?: Partial<PasswordHashOptions>
): { hash: string; salt: string; params: PasswordHashOptions } {
  const validatedOptions = PasswordHashOptionsSchema.parse({
    algorithm: options?.algorithm || 'pbkdf2',
    iterations: options?.iterations || 10000,
    saltLength: options?.saltLength || 32,
    keyLength: options?.keyLength || 64,
  });

  // Generate salt
  const salt = CryptoJS.lib.WordArray.random(validatedOptions.saltLength / 2).toString(
    CryptoJS.enc.Hex
  );

  let hashedPassword: string;

  switch (validatedOptions.algorithm) {
    case 'pbkdf2':
      hashedPassword = CryptoJS.PBKDF2(password, salt, {
        keySize: validatedOptions.keyLength / 4, // keySize is in 32-bit words
        iterations: validatedOptions.iterations,
      }).toString(CryptoJS.enc.Hex);
      break;

    case 'argon2':
      // Note: crypto-js doesn't support Argon2 natively
      // This is a simulation that still uses PBKDF2 with higher iterations
      // For real Argon2, use argon2 npm package
      hashedPassword = CryptoJS.PBKDF2(password, salt, {
        keySize: validatedOptions.keyLength / 4,
        iterations: validatedOptions.iterations * 2, // Higher iterations to simulate Argon2 costs
      }).toString(CryptoJS.enc.Hex);
      break;

    case 'bcrypt':
      // Note: crypto-js doesn't support bcrypt natively
      // This is a simulation that uses PBKDF2 with specific parameters
      // For real bcrypt, use bcrypt npm package
      hashedPassword = CryptoJS.PBKDF2(password, salt, {
        keySize: validatedOptions.keyLength / 4,
        iterations: 1024 + (validatedOptions.iterations % 1024), // bcrypt simulation
      }).toString(CryptoJS.enc.Hex);
      break;

    default:
      hashedPassword = CryptoJS.PBKDF2(password, salt, {
        keySize: validatedOptions.keyLength / 4,
        iterations: validatedOptions.iterations,
      }).toString(CryptoJS.enc.Hex);
  }

  return {
    hash: hashedPassword,
    salt,
    params: validatedOptions,
  };
}

/**
 * Verifies a password against a previously hashed password
 * @param password - The password to verify
 * @param hash - The previously generated hash
 * @param salt - The salt used in the original hash
 * @param options - Password hash options (must match those used in hashPassword)
 * @returns True if the password matches, false otherwise
 */
export function verifyPassword(
  password: string,
  hash: string,
  salt: string,
  options?: Partial<PasswordHashOptions>
): boolean {
  const validatedOptions = PasswordHashOptionsSchema.parse({
    algorithm: options?.algorithm || 'pbkdf2',
    iterations: options?.iterations || 10000,
    saltLength: options?.saltLength || 32,
    keyLength: options?.keyLength || 64,
  });

  const { hash: generatedHash } = hashPassword(password, validatedOptions);

  // Use timingSafeEqual to prevent timing attacks
  return timingSafeEqual(generatedHash, hash);
}

/**
 * Performs a constant-time comparison of two strings to prevent timing attacks
 * @param a - First string to compare
 * @param b - Second string to compare
 * @param options - Timing safe comparison options
 * @returns True if both strings are equal, false otherwise
 */
export function timingSafeEqual(
  a: string,
  b: string,
  options?: Partial<TimingSafeOptions>
): boolean {
  const validatedOptions = TimingSafeOptionsSchema.parse({
    encoding: options?.encoding || 'utf8',
  });

  // Early length check (this is safe since length is already revealed in most contexts)
  if (a.length !== b.length) {
    return false;
  }

  // Convert strings to appropriate encoding if needed
  let bufferA: string = a;
  let bufferB: string = b;

  if (validatedOptions.encoding === 'hex') {
    try {
      bufferA = CryptoJS.enc.Hex.parse(a).toString(CryptoJS.enc.Utf8);
      bufferB = CryptoJS.enc.Hex.parse(b).toString(CryptoJS.enc.Utf8);
    } catch {
      return false; // Invalid hex
    }
  } else if (validatedOptions.encoding === 'base64') {
    try {
      bufferA = CryptoJS.enc.Base64.parse(a).toString(CryptoJS.enc.Utf8);
      bufferB = CryptoJS.enc.Base64.parse(b).toString(CryptoJS.enc.Utf8);
    } catch {
      return false; // Invalid base64
    }
  }

  // Constant-time comparison
  let result = 0;
  for (let i = 0; i < bufferA.length; i++) {
    // XOR each character - it will be 0 only if they are the same
    result |= bufferA.charCodeAt(i) ^ bufferB.charCodeAt(i);
  }

  return result === 0;
}

/**
 * Generates a cryptographically secure random string
 * @param length - The length of the random string in bytes
 * @param encoding - The encoding to use for the output
 * @returns A random string in the specified encoding
 */
export function generateRandomBytes(
  length: number = 32,
  encoding: 'hex' | 'base64' = 'hex'
): string {
  const randomBytes = CryptoJS.lib.WordArray.random(length);
  return encoding === 'base64'
    ? randomBytes.toString(CryptoJS.enc.Base64)
    : randomBytes.toString(CryptoJS.enc.Hex);
}
