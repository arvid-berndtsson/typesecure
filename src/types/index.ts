import { z } from "zod";

// Password strength schema
export const PasswordStrengthSchema = z.object({
  score: z.number().min(0).max(4),
  feedback: z.object({
    warning: z.string().optional(),
    suggestions: z.array(z.string()).optional(),
  }),
  isStrong: z.boolean(),
});

export type PasswordStrength = z.infer<typeof PasswordStrengthSchema>;

// Hash options schema
export const HashOptionsSchema = z.object({
  algorithm: z
    .enum(["md5", "sha1", "sha256", "sha512", "sha3"])
    .default("sha256"),
  encoding: z.enum(["hex", "base64"]).default("hex"),
});

export type HashOptions = z.infer<typeof HashOptionsSchema>;

// Password hash options schema
export const PasswordHashOptionsSchema = z.object({
  algorithm: z.enum(["pbkdf2", "argon2", "bcrypt"]).default("pbkdf2"),
  iterations: z.number().min(1000).default(10000),
  saltLength: z.number().min(16).default(32),
  keyLength: z.number().min(16).default(64),
  saltEncoding: z.enum(["hex", "base64"]).default("hex"),
});

export type PasswordHashOptions = z.infer<typeof PasswordHashOptionsSchema>;

// Time-safe comparison options
export const TimingSafeOptionsSchema = z.object({
  encoding: z.enum(["utf8", "hex", "base64"]).default("utf8"),
});

export type TimingSafeOptions = z.infer<typeof TimingSafeOptionsSchema>;

// Encryption options schema
export const EncryptionOptionsSchema = z.object({
  mode: z.enum(["aes-cbc", "aes-ctr", "aes-ecb", "aes-gcm"]).default("aes-cbc"),
  padding: z.enum(["Pkcs7", "NoPadding", "ZeroPadding"]).default("Pkcs7"),
  iv: z.string().optional(),
  authTag: z.string().optional(),
  aad: z.string().optional(), // Additional authenticated data for GCM mode
});

export type EncryptionOptions = z.infer<typeof EncryptionOptionsSchema>;

// Config schema
export const ConfigSchema = z.object({
  minimumPasswordLength: z.number().min(8).default(12),
  requireNumbers: z.boolean().default(true),
  requireSymbols: z.boolean().default(true),
  requireUppercase: z.boolean().default(true),
  requireLowercase: z.boolean().default(true),
});

export type Config = z.infer<typeof ConfigSchema>;
