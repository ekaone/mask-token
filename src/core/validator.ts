/**
 * mask-token - Secure token masking with NIST/PCI-DSS/OWASP compliance
 *
 * Input validation and risk scoring
 *
 * Feature #3: Leaked Token Detection Hook
 *
 * @module core/validator
 */

import type { ValidationResult, ValidationRules } from "../types";
import {
  MIN_TOKEN_LENGTH,
  MAX_TOKEN_LENGTH,
  MIN_ENTROPY_RATIO,
  RISK_SCORE_THRESHOLDS,
  RISK_WEIGHTS,
  SUSPICIOUS_PATTERNS,
  WARNING_MESSAGES,
  VALIDATION_SUGGESTIONS,
} from "../utils/constants";

// ============================================================================
// MAIN VALIDATION FUNCTION
// ============================================================================

/**
 * Validate input string for token-like characteristics
 *
 * Checks input against multiple criteria to detect potential issues:
 * - Length validation (min/max)
 * - Whitespace detection
 * - Pattern matching (required patterns)
 * - Suspicious content (placeholders, wrong credential types)
 * - Character entropy
 * - Custom validation rules
 *
 * Returns a validation result with warnings, suggestions, and risk score.
 *
 * @param input - String to validate
 * @param rules - Optional validation rules
 * @returns Validation result with warnings and risk score
 *
 * @example
 * ```typescript
 * // Valid token
 * validateInput('npm_a1b2c3d4e5f6g7h8i9j0');
 * // { valid: true, warnings: [], riskScore: 0 }
 *
 * // Placeholder value
 * validateInput('undefined');
 * // {
 * //   valid: false,
 * //   warnings: ['Looks like an undefined or null value'],
 * //   suggestions: ['Replace placeholder with actual token value'],
 * //   riskScore: 50
 * // }
 *
 * // Too short
 * validateInput('abc123', { minLength: 20 });
 * // {
 * //   valid: false,
 * //   warnings: ['Input too short (6 < 20)'],
 * //   suggestions: ['Ensure you are passing the full token string'],
 * //   riskScore: 30
 * // }
 * ```
 */
export function validateInput(
  input: string,
  rules: ValidationRules = {},
): ValidationResult {
  const warnings: string[] = [];
  let riskScore = 0;

  // Early return for empty input
  if (!input || typeof input !== "string") {
    return {
      valid: false,
      warnings: ["Input is empty or not a string"],
      suggestions: ["Provide a valid string input"],
      riskScore: 100,
    };
  }

  // ============================================================================
  // RULE-BASED VALIDATION
  // ============================================================================

  // Check minimum length
  if (rules.minLength !== undefined && input.length < rules.minLength) {
    warnings.push(WARNING_MESSAGES.TOO_SHORT(input.length, rules.minLength));
    riskScore += RISK_WEIGHTS.TOO_SHORT;
  }

  // Check maximum length
  if (rules.maxLength !== undefined && input.length > rules.maxLength) {
    warnings.push(WARNING_MESSAGES.TOO_LONG(input.length, rules.maxLength));
    riskScore += RISK_WEIGHTS.TOO_LONG;
  }

  // Check for whitespace
  if (rules.noSpaces && /\s/.test(input)) {
    warnings.push(WARNING_MESSAGES.HAS_WHITESPACE);
    riskScore += RISK_WEIGHTS.HAS_WHITESPACE;
  }

  // Check for required prefix pattern
  if (rules.requirePrefix && !/^[a-z]{2,6}_/.test(input)) {
    warnings.push(WARNING_MESSAGES.MISSING_PREFIX);
    riskScore += RISK_WEIGHTS.MISSING_PREFIX;
  }

  // Check against required pattern
  if (rules.pattern && !rules.pattern.test(input)) {
    warnings.push(WARNING_MESSAGES.PATTERN_MISMATCH);
    riskScore += RISK_WEIGHTS.PATTERN_MISMATCH;
  }

  // Run custom validation check
  if (rules.customCheck && !rules.customCheck(input)) {
    warnings.push(WARNING_MESSAGES.CUSTOM_CHECK_FAILED);
    riskScore += RISK_WEIGHTS.CUSTOM_CHECK_FAILED;
  }

  // ============================================================================
  // SUSPICIOUS PATTERN DETECTION
  // ============================================================================

  for (const { pattern, message, score } of SUSPICIOUS_PATTERNS) {
    if (pattern.test(input)) {
      warnings.push(message);
      riskScore += score;
    }
  }

  // ============================================================================
  // HEURISTIC CHECKS
  // ============================================================================

  // Check if input is suspiciously short (likely not a real token)
  if (input.length < MIN_TOKEN_LENGTH && !rules.minLength) {
    // Only warn if no explicit minLength rule (avoid duplicate warnings)
    const alreadyWarned = warnings.some((w) => w.includes("too short"));
    if (!alreadyWarned) {
      warnings.push(
        `Input is very short (${input.length} chars) - might not be a real token`,
      );
      riskScore += 25;
    }
  }

  // Check if input is suspiciously long
  if (input.length > MAX_TOKEN_LENGTH && !rules.maxLength) {
    const alreadyWarned = warnings.some((w) => w.includes("too long"));
    if (!alreadyWarned) {
      warnings.push(
        `Input is very long (${input.length} chars) - might be malformed`,
      );
      riskScore += 15;
    }
  }

  // Check entropy (character diversity)
  const entropy = calculateEntropy(input);
  if (entropy < MIN_ENTROPY_RATIO) {
    warnings.push(WARNING_MESSAGES.LOW_ENTROPY);
    riskScore += RISK_WEIGHTS.LOW_ENTROPY;
  }

  // ============================================================================
  // GENERATE SUGGESTIONS
  // ============================================================================

  const suggestions = generateSuggestions(warnings);

  // ============================================================================
  // RETURN RESULT
  // ============================================================================

  // Cap risk score at 100
  riskScore = Math.min(100, riskScore);

  return {
    valid: warnings.length === 0,
    warnings,
    suggestions,
    riskScore,
  };
}

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

/**
 * Calculate entropy (character diversity) of a string
 *
 * Returns ratio of unique characters to total length.
 * Higher values indicate more diversity (better for tokens).
 *
 * @param input - String to analyze
 * @returns Entropy ratio (0-1)
 *
 * @example
 * ```typescript
 * calculateEntropy('aaaaaaaaaa');
 * // 0.1 (only 1 unique char out of 10)
 *
 * calculateEntropy('abcdefghij');
 * // 1.0 (all 10 chars are unique)
 *
 * calculateEntropy('npm_a1b2c3');
 * // 0.9 (9 unique chars out of 10)
 * ```
 *
 * @internal
 */
function calculateEntropy(input: string): number {
  if (!input || input.length === 0) {
    return 0;
  }

  const uniqueChars = new Set(input).size;
  return uniqueChars / input.length;
}

/**
 * Generate helpful suggestions based on warnings
 *
 * Maps warning messages to actionable suggestions for the user.
 *
 * @param warnings - Array of warning messages
 * @returns Array of suggestions
 *
 * @example
 * ```typescript
 * generateSuggestions(['Input too short', 'Contains whitespace']);
 * // [
 * //   'Ensure you are passing the full token string',
 * //   'Trim whitespace from token before masking'
 * // ]
 * ```
 *
 * @internal
 */
export function generateSuggestions(warnings: string[]): string[] {
  const suggestions: string[] = [];
  const suggestionSet = new Set<string>(); // Avoid duplicates

  for (const warning of warnings) {
    let suggestion: string | undefined;

    // Map warnings to suggestions
    if (warning.includes("too short")) {
      suggestion = VALIDATION_SUGGESTIONS.TOO_SHORT;
    } else if (warning.includes("too long")) {
      suggestion = VALIDATION_SUGGESTIONS.TOO_LONG;
    } else if (warning.includes("whitespace")) {
      suggestion = VALIDATION_SUGGESTIONS.HAS_WHITESPACE;
    } else if (warning.includes("prefix")) {
      suggestion = VALIDATION_SUGGESTIONS.MISSING_PREFIX;
    } else if (warning.includes("pattern")) {
      suggestion = VALIDATION_SUGGESTIONS.PATTERN_MISMATCH;
    } else if (warning.includes("custom")) {
      suggestion = VALIDATION_SUGGESTIONS.CUSTOM_CHECK_FAILED;
    } else if (
      warning.includes("placeholder") ||
      warning.includes("undefined") ||
      warning.includes("null")
    ) {
      suggestion = VALIDATION_SUGGESTIONS.PLACEHOLDER_DETECTED;
    } else if (
      warning.includes("password") ||
      warning.includes("username") ||
      warning.includes("credential")
    ) {
      suggestion = VALIDATION_SUGGESTIONS.WRONG_CREDENTIAL_TYPE;
    } else if (warning.includes("entropy") || warning.includes("diversity")) {
      suggestion = VALIDATION_SUGGESTIONS.LOW_ENTROPY;
    }

    if (suggestion && !suggestionSet.has(suggestion)) {
      suggestions.push(suggestion);
      suggestionSet.add(suggestion);
    }
  }

  return suggestions;
}

// ============================================================================
// RISK ASSESSMENT
// ============================================================================

/**
 * Get risk level from risk score
 *
 * Categorizes risk score into severity levels.
 *
 * @param riskScore - Risk score (0-100)
 * @returns Risk level string
 *
 * @example
 * ```typescript
 * getRiskLevel(0);   // 'low'
 * getRiskLevel(25);  // 'medium'
 * getRiskLevel(60);  // 'high'
 * getRiskLevel(90);  // 'critical'
 * ```
 */
export function getRiskLevel(
  riskScore: number,
): "low" | "medium" | "high" | "critical" {
  if (riskScore <= RISK_SCORE_THRESHOLDS.LOW) {
    return "low";
  } else if (riskScore <= RISK_SCORE_THRESHOLDS.MEDIUM) {
    return "medium";
  } else if (riskScore <= RISK_SCORE_THRESHOLDS.HIGH) {
    return "high";
  } else {
    return "critical";
  }
}

/**
 * Check if input is likely a valid token
 *
 * Quick validation check without detailed warnings.
 * Useful for fast filtering.
 *
 * @param input - String to check
 * @returns true if input looks like a token
 *
 * @example
 * ```typescript
 * isLikelyValid('npm_a1b2c3d4e5f6g7h8i9j0');
 * // true
 *
 * isLikelyValid('hello world');
 * // false
 *
 * isLikelyValid('undefined');
 * // false
 * ```
 */
export function isLikelyValid(input: string): boolean {
  const result = validateInput(input);
  return result.riskScore <= RISK_SCORE_THRESHOLDS.MEDIUM;
}

// ============================================================================
// COMMON VALIDATION PRESETS
// ============================================================================

/**
 * Strict validation rules for production environments
 *
 * @example
 * ```typescript
 * const result = validateInput(token, STRICT_VALIDATION);
 * if (!result.valid) {
 *   console.error('Invalid token:', result.warnings);
 * }
 * ```
 */
export const STRICT_VALIDATION: ValidationRules = {
  minLength: MIN_TOKEN_LENGTH,
  maxLength: MAX_TOKEN_LENGTH,
  noSpaces: true,
  requirePrefix: true,
};

/**
 * Lenient validation rules for development
 *
 * @example
 * ```typescript
 * const result = validateInput(token, LENIENT_VALIDATION);
 * // Only checks basic format
 * ```
 */
export const LENIENT_VALIDATION: ValidationRules = {
  minLength: 8,
  noSpaces: true,
};

/**
 * Balanced validation rules for general use
 *
 * @example
 * ```typescript
 * const result = validateInput(token, BALANCED_VALIDATION);
 * ```
 */
export const BALANCED_VALIDATION: ValidationRules = {
  minLength: 12,
  maxLength: MAX_TOKEN_LENGTH,
  noSpaces: true,
};

// ============================================================================
// BATCH VALIDATION
// ============================================================================

/**
 * Validate multiple inputs at once
 *
 * Useful for batch processing or checking multiple tokens.
 *
 * @param inputs - Array of strings to validate
 * @param rules - Validation rules to apply to all inputs
 * @returns Array of validation results
 *
 * @example
 * ```typescript
 * const tokens = ['npm_abc123', 'undefined', 'ghp_xyz789'];
 * const results = validateBatch(tokens);
 *
 * results.forEach((result, index) => {
 *   if (!result.valid) {
 *     console.log(`Token ${index} is invalid:`, result.warnings);
 *   }
 * });
 * ```
 */
export function validateBatch(
  inputs: string[],
  rules?: ValidationRules,
): ValidationResult[] {
  return inputs.map((input) => validateInput(input, rules));
}

/**
 * Get summary statistics for batch validation
 *
 * @param results - Array of validation results
 * @returns Summary statistics
 *
 * @example
 * ```typescript
 * const tokens = ['npm_abc123', 'undefined', 'ghp_xyz789'];
 * const results = validateBatch(tokens);
 * const summary = getBatchSummary(results);
 *
 * console.log(summary);
 * // {
 * //   total: 3,
 * //   valid: 2,
 * //   invalid: 1,
 * //   averageRiskScore: 16.7,
 * //   highRiskCount: 1
 * // }
 * ```
 */
export function getBatchSummary(results: ValidationResult[]): {
  total: number;
  valid: number;
  invalid: number;
  averageRiskScore: number;
  highRiskCount: number;
} {
  const total = results.length;
  const valid = results.filter((r) => r.valid).length;
  const invalid = total - valid;
  const totalRisk = results.reduce((sum, r) => sum + r.riskScore, 0);
  const averageRiskScore = total > 0 ? totalRisk / total : 0;
  const highRiskCount = results.filter(
    (r) => r.riskScore > RISK_SCORE_THRESHOLDS.HIGH,
  ).length;

  return {
    total,
    valid,
    invalid,
    averageRiskScore: Math.round(averageRiskScore * 10) / 10, // Round to 1 decimal
    highRiskCount,
  };
}
