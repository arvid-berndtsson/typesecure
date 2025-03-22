import {
  Config,
  ConfigSchema,
  PasswordStrength,
  PasswordStrengthSchema,
} from "../types";

/**
 * Calculates the entropy of a password in bits
 * @param password - The password to calculate entropy for
 * @returns The entropy in bits
 */
export function calculatePasswordEntropy(password: string): number {
  if (!password || password.length === 0) return 0;

  // Calculate character pool size based on character types used
  let poolSize = 0;

  const hasLowercase = /[a-z]/.test(password);
  const hasUppercase = /[A-Z]/.test(password);
  const hasDigits = /\d/.test(password);
  const hasSymbols = /[^A-Za-z0-9]/.test(password);

  if (hasLowercase) poolSize += 26;
  if (hasUppercase) poolSize += 26;
  if (hasDigits) poolSize += 10;
  if (hasSymbols) poolSize += 33; // Approximate for common symbols

  // Shannon entropy formula: E = L * log2(R)
  // where L is password length and R is pool size
  const entropy = password.length * Math.log2(poolSize);

  return Math.round(entropy * 100) / 100; // Round to 2 decimal places
}

/**
 * Analyzes patterns in the password that might reduce its effective entropy
 * @param password - The password to analyze
 * @returns The entropy reduction (0 to 1)
 */
export function analyzePasswordPatterns(password: string): {
  entropyReduction: number;
  patterns: string[];
} {
  const patterns: string[] = [];
  let entropyReduction = 0;

  // Check for keyboard patterns
  const keyboardPatterns = [
    "qwerty",
    "asdfgh",
    "zxcvbn",
    "qwertz",
    "azerty",
    "123456",
    "654321",
  ];

  // Check for sequential characters
  const sequentialCheck = (pwd: string): boolean => {
    for (let i = 0; i < pwd.length - 2; i++) {
      const c1 = pwd.charCodeAt(i);
      const c2 = pwd.charCodeAt(i + 1);
      const c3 = pwd.charCodeAt(i + 2);

      if (
        (c1 + 1 === c2 && c2 + 1 === c3) ||
        (c1 - 1 === c2 && c2 - 1 === c3)
      ) {
        return true;
      }
    }
    return false;
  };

  // Check for repeated patterns
  const repeatedPatternCheck = (pwd: string): boolean => {
    if (pwd.length <= 2) return false;

    // Check for repeating substrings
    for (let len = 2; len <= pwd.length / 2; len++) {
      for (let i = 0; i <= pwd.length - len * 2; i++) {
        const pattern = pwd.substring(i, i + len);
        const nextPart = pwd.substring(i + len, i + len * 2);
        if (pattern === nextPart) {
          return true;
        }
      }
    }
    return false;
  };

  // Check for common patterns
  for (const pattern of keyboardPatterns) {
    if (password.toLowerCase().includes(pattern)) {
      patterns.push("Contains keyboard pattern");
      entropyReduction += 0.2;
      break;
    }
  }

  // Check for sequential characters
  if (sequentialCheck(password)) {
    patterns.push("Contains sequential characters");
    entropyReduction += 0.15;
  }

  // Check for repeated patterns
  if (repeatedPatternCheck(password)) {
    patterns.push("Contains repeated patterns");
    entropyReduction += 0.2;
  }

  // Check for common substitutions (l33t speak)
  const l33tMap: Record<string, string> = {
    "4": "a",
    "@": "a",
    "8": "b",
    "3": "e",
    "6": "g",
    "1": "i",
    "!": "i",
    "0": "o",
    "9": "g",
    $: "s",
    "5": "s",
    "+": "t",
    "7": "t",
    "%": "x",
    "2": "z",
  };

  let transformedPassword = password.toLowerCase();
  for (const [digit, letter] of Object.entries(l33tMap)) {
    // Need to escape special characters in the regex
    const safeDigit = digit.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    transformedPassword = transformedPassword.replace(
      new RegExp(safeDigit, "g"),
      letter
    );
  }

  // Check if the transformed password contains dictionary words
  const commonWords = [
    "password",
    "admin",
    "user",
    "login",
    "welcome",
    "secure",
    "secret",
  ];

  for (const word of commonWords) {
    if (transformedPassword.includes(word)) {
      patterns.push("Contains common word with substitutions");
      entropyReduction += 0.25;
      break;
    }
  }

  // Check if the password is primarily one character type
  if (
    /^[a-z]+$/.test(password) ||
    /^[A-Z]+$/.test(password) ||
    /^[0-9]+$/.test(password) ||
    /^[^A-Za-z0-9]+$/.test(password)
  ) {
    patterns.push("Uses only one character type");
    entropyReduction += 0.3;
  }

  // Cap the total reduction
  entropyReduction = Math.min(entropyReduction, 0.9);

  return { entropyReduction, patterns };
}

/**
 * Checks the strength of a password using both rule-based criteria and entropy
 * @param password - The password to check
 * @param config - Password configuration options
 * @returns A PasswordStrength object containing score and feedback
 */
export function checkPasswordStrength(
  password: string,
  config?: Partial<Config>
): PasswordStrength {
  const validatedConfig = ConfigSchema.parse({
    minimumPasswordLength: config?.minimumPasswordLength || 12,
    requireNumbers:
      config?.requireNumbers !== undefined ? config.requireNumbers : true,
    requireSymbols:
      config?.requireSymbols !== undefined ? config.requireSymbols : true,
    requireUppercase:
      config?.requireUppercase !== undefined ? config.requireUppercase : true,
    requireLowercase:
      config?.requireLowercase !== undefined ? config.requireLowercase : true,
  });

  const hasMinLength = password.length >= validatedConfig.minimumPasswordLength;
  const hasNumbers = /\d/.test(password);
  const hasSymbols = /[^A-Za-z0-9]/.test(password);
  const hasUppercase = /[A-Z]/.test(password);
  const hasLowercase = /[a-z]/.test(password);

  // Check required criteria
  const suggestions: string[] = [];
  let warning = "";

  // Calculate base criteria score
  let criteriaCount = 0;
  if (hasMinLength) criteriaCount++;
  if (hasNumbers && validatedConfig.requireNumbers) criteriaCount++;
  if (hasSymbols && validatedConfig.requireSymbols) criteriaCount++;
  if (hasUppercase && validatedConfig.requireUppercase) criteriaCount++;
  if (hasLowercase && validatedConfig.requireLowercase) criteriaCount++;

  // Handle specific failures
  if (!hasMinLength) {
    warning = "Password is too short";
    suggestions.push(
      `Password should be at least ${validatedConfig.minimumPasswordLength} characters long`
    );
  }

  if (validatedConfig.requireNumbers && !hasNumbers) {
    suggestions.push("Add numbers to make your password stronger");
  }

  if (validatedConfig.requireSymbols && !hasSymbols) {
    suggestions.push("Add symbols to make your password stronger");
  }

  if (validatedConfig.requireUppercase && !hasUppercase) {
    suggestions.push("Add uppercase letters to make your password stronger");
  }

  if (validatedConfig.requireLowercase && !hasLowercase) {
    suggestions.push("Add lowercase letters to make your password stronger");
  }

  // Calculate entropy and analyze patterns
  const entropy = calculatePasswordEntropy(password);
  const { entropyReduction, patterns } = analyzePasswordPatterns(password);
  const effectiveEntropy = entropy * (1 - entropyReduction);

  // Add pattern-based suggestions
  suggestions.push(
    ...patterns.map((p) => `${p}: Consider a more random pattern`)
  );

  // Determine score based on entropy and criteria
  let score: number;

  if (effectiveEntropy < 28) {
    score = 0; // Very weak
    if (!warning) warning = "Very weak password";
  } else if (effectiveEntropy < 36) {
    score = 1; // Weak
    if (!warning) warning = "Weak password";
  } else if (effectiveEntropy < 60) {
    score = 2; // Medium
  } else if (effectiveEntropy < 80) {
    score = 3; // Strong
  } else {
    score = 4; // Very strong
  }

  // Criteria can boost the score, but not above 4
  const criteriaBoost = criteriaCount >= 5 ? 1 : 0;
  score = Math.min(4, score + criteriaBoost);

  // But if critical criteria are missing, cap the score
  if (
    !hasMinLength ||
    (validatedConfig.requireNumbers && !hasNumbers) ||
    (validatedConfig.requireSymbols && !hasSymbols) ||
    (validatedConfig.requireUppercase && !hasUppercase) ||
    (validatedConfig.requireLowercase && !hasLowercase)
  ) {
    score = Math.min(score, 2); // Cap at medium if requirements not met
  }

  // Add entropy-based suggestions
  if (effectiveEntropy < 50) {
    suggestions.push(
      `Increase password entropy (currently ~${Math.round(
        effectiveEntropy
      )} bits)`
    );
  }

  // Determine if password is strong enough
  const isStrong =
    hasMinLength &&
    (!validatedConfig.requireNumbers || hasNumbers) &&
    (!validatedConfig.requireSymbols || hasSymbols) &&
    (!validatedConfig.requireUppercase || hasUppercase) &&
    (!validatedConfig.requireLowercase || hasLowercase) &&
    score >= 3; // Also require a high score

  return PasswordStrengthSchema.parse({
    score,
    feedback: {
      warning,
      suggestions: suggestions.length > 0 ? suggestions : undefined,
    },
    isStrong,
  });
}

/**
 * Generates a secure random password based on configuration
 * @param config - Password configuration options
 * @returns A random secure password
 */
export function generateSecurePassword(config?: Partial<Config>): string {
  const validatedConfig = ConfigSchema.parse({
    minimumPasswordLength: config?.minimumPasswordLength || 12,
    requireNumbers:
      config?.requireNumbers !== undefined ? config.requireNumbers : true,
    requireSymbols:
      config?.requireSymbols !== undefined ? config.requireSymbols : true,
    requireUppercase:
      config?.requireUppercase !== undefined ? config.requireUppercase : true,
    requireLowercase:
      config?.requireLowercase !== undefined ? config.requireLowercase : true,
  });

  const length = validatedConfig.minimumPasswordLength;

  const lowercaseChars = "abcdefghijklmnopqrstuvwxyz";
  const uppercaseChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
  const numbers = "0123456789";
  const symbols = "!@#$%^&*()_+-=[]{}|;:,.<>?";

  let characters = "";
  let password = "";

  if (validatedConfig.requireLowercase) characters += lowercaseChars;
  if (validatedConfig.requireUppercase) characters += uppercaseChars;
  if (validatedConfig.requireNumbers) characters += numbers;
  if (validatedConfig.requireSymbols) characters += symbols;

  // Ensure at least one character from each required set
  if (validatedConfig.requireLowercase) {
    password += lowercaseChars.charAt(
      Math.floor(Math.random() * lowercaseChars.length)
    );
  }

  if (validatedConfig.requireUppercase) {
    password += uppercaseChars.charAt(
      Math.floor(Math.random() * uppercaseChars.length)
    );
  }

  if (validatedConfig.requireNumbers) {
    password += numbers.charAt(Math.floor(Math.random() * numbers.length));
  }

  if (validatedConfig.requireSymbols) {
    password += symbols.charAt(Math.floor(Math.random() * symbols.length));
  }

  // Fill the rest with random characters
  for (let i = password.length; i < length; i++) {
    password += characters.charAt(
      Math.floor(Math.random() * characters.length)
    );
  }

  // Shuffle the password to avoid predictable patterns
  return shuffleString(password);
}

/**
 * Shuffles the characters in a string
 * @param str - The string to shuffle
 * @returns A shuffled version of the input string
 */
function shuffleString(str: string): string {
  const array = str.split("");

  for (let i = array.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [array[i], array[j]] = [array[j], array[i]];
  }

  return array.join("");
}
