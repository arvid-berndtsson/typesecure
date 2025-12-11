import CryptoJS from 'crypto-js';
import { EncryptionOptions, EncryptionOptionsSchema } from '../types';

/**
 * A const enum for security levels, used for warnings
 * @public
 */
export enum SecurityLevel {
  HIGH = 'HIGH',
  MEDIUM = 'MEDIUM',
  LOW = 'LOW',
  INSECURE = 'INSECURE',
}

/**
 * Returns the security level of the encryption options
 * @param options - The encryption options
 * @returns The security level
 */
export function getSecurityLevel(options: EncryptionOptions): SecurityLevel {
  if (options.mode === 'aes-gcm') {
    return SecurityLevel.HIGH;
  }

  if (options.mode === 'aes-cbc' || options.mode === 'aes-ctr') {
    return SecurityLevel.HIGH; // CBC and CTR are secure when properly implemented
  }

  if (options.mode === 'aes-ecb') {
    return SecurityLevel.INSECURE; // ECB mode is insecure for most purposes
  }

  // Default case for unrecognized modes
  return SecurityLevel.LOW;
}

/**
 * Logs a security warning based on the encryption options
 * @param options - The encryption options
 */
function logSecurityWarning(options: EncryptionOptions): void {
  const securityLevel = getSecurityLevel(options);

  switch (securityLevel) {
    case SecurityLevel.INSECURE:
      console.warn(
        `⚠️ SECURITY WARNING: ${options.mode} mode is insecure and should not be used in production!`
      );
      break;
    case SecurityLevel.LOW:
      console.warn(
        `⚠️ Security Warning: ${options.mode} with ${options.padding} padding provides low security.`
      );
      break;
    case SecurityLevel.MEDIUM:
      console.info(
        `ℹ️ Security Note: ${options.mode} with ${options.padding} padding provides adequate security for most use cases.`
      );
      break;
    case SecurityLevel.HIGH:
      // No warning needed for high security
      break;
  }
}

/**
 * Encrypts the provided text using the specified encryption options
 * @param text - The text to encrypt
 * @param key - The encryption key
 * @param options - Encryption options
 * @returns The encrypted text
 */
export function encrypt(text: string, key: string, options?: Partial<EncryptionOptions>): string {
  const validatedOptions = EncryptionOptionsSchema.parse({
    mode: options?.mode || 'aes-cbc',
    padding: options?.padding || 'Pkcs7',
    iv: options?.iv,
    authTag: options?.authTag,
    aad: options?.aad,
  });

  // Log security warning if applicable
  logSecurityWarning(validatedOptions);

  const keyWordArray = CryptoJS.enc.Utf8.parse(key);
  let encrypted: CryptoJS.lib.CipherParams;

  // Configure padding
  const paddingOption = CryptoJS.pad[validatedOptions.padding];

  switch (validatedOptions.mode) {
    case 'aes-gcm': {
      // For GCM mode, we need an initialization vector
      const iv = validatedOptions.iv
        ? CryptoJS.enc.Utf8.parse(validatedOptions.iv)
        : CryptoJS.lib.WordArray.random(12); // 12 bytes (96 bits) is recommended for GCM

      // Additional authenticated data (AAD) - optional
      const aad = validatedOptions.aad ? CryptoJS.enc.Utf8.parse(validatedOptions.aad) : undefined;

      // GCM mode is not directly supported in CryptoJS, so we simulate it
      // In a production environment, consider using the Web Crypto API or a native Node.js crypto for GCM
      encrypted = CryptoJS.AES.encrypt(text, keyWordArray, {
        iv,
        mode: CryptoJS.mode.CTR, // Use CTR as a base for GCM simulation
        padding: paddingOption,
      });

      // Compute authentication tag (GMAC)
      // This is a simplified simulation - real GCM combines CTR + GHASH
      const authData = aad ? aad.concat(encrypted.ciphertext) : encrypted.ciphertext;
      const authTag = CryptoJS.HmacSHA256(authData, keyWordArray).toString().substring(0, 32);

      // Include IV and auth tag with the output
      const ivHex = iv.toString(CryptoJS.enc.Hex);
      return `${ivHex}:${authTag}:${encrypted.toString()}`;
    }
    case 'aes-cbc': {
      // For CBC mode, we need an initialization vector
      const iv = validatedOptions.iv
        ? CryptoJS.enc.Utf8.parse(validatedOptions.iv)
        : CryptoJS.lib.WordArray.random(16); // Generate a random IV if not provided

      encrypted = CryptoJS.AES.encrypt(text, keyWordArray, {
        iv,
        padding: paddingOption,
        mode: CryptoJS.mode.CBC,
      });

      // Include the IV with the encrypted output if it was generated
      if (!validatedOptions.iv) {
        const ivHex = iv.toString(CryptoJS.enc.Hex);
        return `${ivHex}:${encrypted.toString()}`;
      }
      break;
    }
    case 'aes-ctr': {
      const iv = validatedOptions.iv
        ? CryptoJS.enc.Utf8.parse(validatedOptions.iv)
        : CryptoJS.lib.WordArray.random(16);

      encrypted = CryptoJS.AES.encrypt(text, keyWordArray, {
        iv,
        padding: paddingOption,
        mode: CryptoJS.mode.CTR,
      });

      if (!validatedOptions.iv) {
        const ivHex = iv.toString(CryptoJS.enc.Hex);
        return `${ivHex}:${encrypted.toString()}`;
      }
      break;
    }
    case 'aes-ecb':
      // ECB mode does not use an IV (less secure, but included for compatibility)
      encrypted = CryptoJS.AES.encrypt(text, keyWordArray, {
        padding: paddingOption,
        mode: CryptoJS.mode.ECB,
      });
      break;
    default:
      throw new Error(`Unsupported encryption mode: ${validatedOptions.mode}`);
  }

  return encrypted.toString();
}

/**
 * Decrypts the provided encrypted text using the specified options
 * @param encryptedText - The text to decrypt
 * @param key - The decryption key
 * @param options - Encryption options
 * @returns The decrypted text
 */
export function decrypt(
  encryptedText: string,
  key: string,
  options?: Partial<EncryptionOptions>
): string {
  const validatedOptions = EncryptionOptionsSchema.parse({
    mode: options?.mode || 'aes-cbc',
    padding: options?.padding || 'Pkcs7',
    iv: options?.iv,
    authTag: options?.authTag,
    aad: options?.aad,
  });

  const keyWordArray = CryptoJS.enc.Utf8.parse(key);
  let cipherText = encryptedText;
  let iv: CryptoJS.lib.WordArray | undefined;
  let authTag: string | undefined;

  // Extract IV and auth tag from the encrypted text
  if (validatedOptions.mode === 'aes-gcm' && encryptedText.includes(':')) {
    const parts = encryptedText.split(':');
    if (parts.length >= 3) {
      const ivHex = parts[0];
      authTag = parts[1];
      cipherText = parts[2];
      iv = CryptoJS.enc.Hex.parse(ivHex);
    }
  } else if (encryptedText.includes(':') && !validatedOptions.iv) {
    const parts = encryptedText.split(':');
    const ivHex = parts[0];
    cipherText = parts[1];
    iv = CryptoJS.enc.Hex.parse(ivHex);
  } else if (validatedOptions.iv) {
    iv = CryptoJS.enc.Utf8.parse(validatedOptions.iv);
  }

  // Configure padding
  const paddingOption = CryptoJS.pad[validatedOptions.padding];

  let decrypted: CryptoJS.lib.WordArray;

  switch (validatedOptions.mode) {
    case 'aes-gcm': {
      if (!iv) {
        throw new Error('IV is required for GCM mode decryption');
      }

      if (!authTag && !validatedOptions.authTag) {
        throw new Error('Authentication tag is required for GCM mode decryption');
      }

      const actualAuthTag = authTag || validatedOptions.authTag;

      // Additional authenticated data (AAD)
      const aad = validatedOptions.aad ? CryptoJS.enc.Utf8.parse(validatedOptions.aad) : undefined;

      // First decrypt using CTR mode (part of GCM)
      decrypted = CryptoJS.AES.decrypt(cipherText, keyWordArray, {
        iv,
        mode: CryptoJS.mode.CTR,
        padding: paddingOption,
      });

      // Verify authentication tag
      const cipherTextObj = CryptoJS.enc.Base64.parse(cipherText);
      const authData = aad ? aad.concat(cipherTextObj) : cipherTextObj;
      const calculatedAuthTag = CryptoJS.HmacSHA256(authData, keyWordArray)
        .toString()
        .substring(0, 32);

      if (calculatedAuthTag !== actualAuthTag) {
        throw new Error('Authentication failed: Invalid authentication tag');
      }
      break;
    }
    case 'aes-cbc':
      if (!iv && validatedOptions.mode === 'aes-cbc') {
        throw new Error('IV is required for CBC mode decryption');
      }

      decrypted = CryptoJS.AES.decrypt(cipherText, keyWordArray, {
        iv,
        padding: paddingOption,
        mode: CryptoJS.mode.CBC,
      });
      break;
    case 'aes-ctr':
      if (!iv && validatedOptions.mode === 'aes-ctr') {
        throw new Error('IV is required for CTR mode decryption');
      }

      decrypted = CryptoJS.AES.decrypt(cipherText, keyWordArray, {
        iv,
        padding: paddingOption,
        mode: CryptoJS.mode.CTR,
      });
      break;
    case 'aes-ecb':
      // Log warning for ECB mode
      console.warn(
        '⚠️ WARNING: ECB mode does not provide semantic security and should not be used in most applications'
      );

      decrypted = CryptoJS.AES.decrypt(cipherText, keyWordArray, {
        padding: paddingOption,
        mode: CryptoJS.mode.ECB,
      });
      break;
    default:
      throw new Error(`Unsupported encryption mode: ${validatedOptions.mode}`);
  }

  try {
    return decrypted.toString(CryptoJS.enc.Utf8);
  } catch {
    throw new Error('Failed to decrypt: Invalid key or corrupted data');
  }
}

/**
 * Encrypts a JSON-serializable value and returns the ciphertext.
 * @param payload - The value to serialize and encrypt
 * @param key - The encryption key
 * @param options - Encryption options
 */
export function encryptJson<T>(
  payload: T,
  key: string,
  options?: Partial<EncryptionOptions>
): string {
  const serialized = JSON.stringify(payload);
  return encrypt(serialized, key, options);
}

/**
 * Decrypts the provided ciphertext and parses the resulting JSON payload.
 * @param encryptedPayload - The encrypted JSON string
 * @param key - The decryption key
 * @param options - Encryption options
 * @returns The parsed JSON payload
 */
export function decryptJson<T>(
  encryptedPayload: string,
  key: string,
  options?: Partial<EncryptionOptions>
): T {
  const decrypted = decrypt(encryptedPayload, key, options);

  try {
    return JSON.parse(decrypted) as T;
  } catch {
    throw new Error('Failed to parse decrypted JSON payload');
  }
}

/**
 * Generates a random encryption key
 * @param length - Length of the key in bytes
 * @returns A random key as a hex string
 */
export function generateKey(length: number = 32): string {
  return CryptoJS.lib.WordArray.random(length).toString(CryptoJS.enc.Hex);
}
