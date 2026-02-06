/**
 * mask-token - Secure token masking with NIST/PCI-DSS/OWASP compliance
 *
 * Constants and default values
 *
 * @module utils/constants
 */

import type { MaskOptions, MaskChar, SecurityLevel } from "../types";

// ============================================================================
// DEFAULT MASKING OPTIONS
// ============================================================================

/**
 * Default masking character (bullet point)
 *
 * Chosen for:
 * - Professional appearance
 * - Clear visual distinction from alphanumeric characters
 * - Widely supported across fonts and platforms
 * - Accessibility-friendly (screen readers handle well)
 */
export const DEFAULT_MASK_CHAR: MaskChar = "•";

/**
 * Default fixed mask length (entropy-safe)
 *
 * 8 characters chosen as optimal balance between:
 * - Security: Long enough to hide entropy
 * - UX: Short enough to not dominate the display
 * - Consistency: Standard across industry (GitHub, npm, etc.)
 */
export const DEFAULT_FIXED_LENGTH = 8;

/**
 * Default number of characters to show from tail (end)
 *
 * 4 characters is industry standard:
 * - Credit cards: Show last 4 digits
 * - API keys: Show last 4 chars for verification
 * - Balances security with usability (can identify token)
 */
export const DEFAULT_SHOW_TAIL = 4;

/**
 * Default number of characters to show from head (start, after prefix)
 *
 * 0 characters by default for maximum security.
 * Prefix preservation handles context (npm_, ghp_, etc.)
 */
export const DEFAULT_SHOW_HEAD = 0;

/**
 * Default prefix preservation setting
 *
 * True by default - automatically detect and preserve known prefixes.
 * This is Feature #1 (Automated Known-Prefix Preservation).
 */
export const DEFAULT_PRESERVE_PREFIX = true;

/**
 * Default validation warning setting
 *
 * False by default - don't warn unless explicitly enabled.
 * Users opt-in to validation warnings (Feature #3).
 */
export const DEFAULT_WARN_IF_PLAIN = false;

/**
 * Default masking mode
 *
 * 'auto' mode automatically detects token type and applies appropriate masking.
 */
export const DEFAULT_MODE = "auto" as const;

/**
 * Default metadata inclusion
 *
 * False by default - return simple string for better performance.
 * Users opt-in to metadata when needed.
 */
export const DEFAULT_INCLUDE_METADATA = false;

/**
 * Complete default options object
 *
 * Used as base configuration when merging user options.
 * Ensures all required properties have sensible defaults.
 */
export const DEFAULT_OPTIONS: Required<
  Omit<
    MaskOptions,
    "preset" | "onWarning" | "customPrefixes" | "validators" | "segments"
  >
> = {
  fixedLength: DEFAULT_FIXED_LENGTH,
  showTail: DEFAULT_SHOW_TAIL,
  showHead: DEFAULT_SHOW_HEAD,
  maskChar: DEFAULT_MASK_CHAR,
  preservePrefix: DEFAULT_PRESERVE_PREFIX,
  warnIfPlain: DEFAULT_WARN_IF_PLAIN,
  mode: DEFAULT_MODE,
  includeMetadata: DEFAULT_INCLUDE_METADATA,
};

// ============================================================================
// MASKING CHARACTERS
// ============================================================================

/**
 * Available masking characters with descriptions
 *
 * Provides metadata for each masking character option.
 * Useful for UI pickers or documentation.
 */
export const MASK_CHARACTERS = {
  bullet: {
    char: "•" as MaskChar,
    name: "Bullet",
    description: "Professional, default choice",
    unicode: "U+2022",
  },
  asterisk: {
    char: "*" as MaskChar,
    name: "Asterisk",
    description: "Traditional masking character",
    unicode: "U+002A",
  },
  times: {
    char: "×" as MaskChar,
    name: "Multiplication Sign",
    description: "Alternative symbol",
    unicode: "U+00D7",
  },
  line: {
    char: "─" as MaskChar,
    name: "Horizontal Line",
    description: "Continuous appearance",
    unicode: "U+2500",
  },
} as const;

/**
 * List of all predefined masking characters
 */
export const PREDEFINED_MASK_CHARS: readonly MaskChar[] = [
  MASK_CHARACTERS.bullet.char,
  MASK_CHARACTERS.asterisk.char,
  MASK_CHARACTERS.times.char,
  MASK_CHARACTERS.line.char,
] as const;

// ============================================================================
// SECURITY LEVELS
// ============================================================================

/**
 * Security level names
 *
 * Used for validation and documentation.
 */
export const SECURITY_LEVELS: readonly SecurityLevel[] = [
  "strict",
  "balanced",
  "lenient",
  "ui",
] as const;

/**
 * Security level descriptions
 *
 * Human-readable explanations of each security level.
 */
export const SECURITY_LEVEL_DESCRIPTIONS: Record<SecurityLevel, string> = {
  strict:
    "Maximum security, minimal exposure - ideal for production logs and compliance",
  balanced: "Balance between security and usability - good for general use",
  lenient: "More visible for debugging - use in development only",
  ui: "Optimized for user interface display - balanced visibility",
};

// ============================================================================
// VALIDATION CONSTANTS
// ============================================================================

/**
 * Minimum reasonable token length
 *
 * Tokens shorter than this are likely not real tokens.
 * Used in validation heuristics.
 */
export const MIN_TOKEN_LENGTH = 16;

/**
 * Maximum reasonable token length
 *
 * Tokens longer than this might be malformed or not tokens.
 * Reasonable upper bound for most API keys/tokens.
 */
export const MAX_TOKEN_LENGTH = 2048;

/**
 * Minimum entropy ratio for token detection
 *
 * Ratio of unique characters to total length.
 * Real tokens should have at least 30% unique characters.
 *
 * Example:
 * - "aaaaaaaaaa" has 1/10 = 0.1 entropy (not a token)
 * - "a1b2c3d4e5" has 10/10 = 1.0 entropy (likely a token)
 * - "npm_abc123" has 9/10 = 0.9 entropy (definitely a token)
 */
export const MIN_ENTROPY_RATIO = 0.3;

/**
 * Risk score thresholds
 *
 * Used to categorize validation results by severity.
 */
export const RISK_SCORE_THRESHOLDS = {
  LOW: 20, // 0-20: Likely valid token
  MEDIUM: 50, // 21-50: Suspicious but might be valid
  HIGH: 80, // 51-80: Probably not a token
  CRITICAL: 100, // 81-100: Definitely not a token
} as const;

/**
 * Risk score weights for different validation failures
 *
 * How much each type of failure contributes to the risk score.
 */
export const RISK_WEIGHTS = {
  TOO_SHORT: 30,
  TOO_LONG: 10,
  HAS_WHITESPACE: 40,
  MISSING_PREFIX: 20,
  PATTERN_MISMATCH: 25,
  CUSTOM_CHECK_FAILED: 30,
  PLACEHOLDER_DETECTED: 50,
  WRONG_CREDENTIAL_TYPE: 40,
  MULTIPLE_SPACES: 35,
  LOW_ENTROPY: 35,
} as const;

// ============================================================================
// SUSPICIOUS PATTERNS
// ============================================================================

/**
 * Patterns that indicate placeholder or test values
 *
 * Used in validation to detect common mistakes where developers
 * accidentally pass placeholder values instead of real tokens.
 */
export const SUSPICIOUS_PATTERNS = [
  {
    pattern: /^(undefined|null)$/i,
    message: "Looks like an undefined or null value",
    score: RISK_WEIGHTS.PLACEHOLDER_DETECTED,
  },
  {
    pattern:
      /^(test|example|sample|demo|placeholder|your[_-]?token|xxx+|000+)/i,
    message: "Looks like a placeholder or test value",
    score: RISK_WEIGHTS.PLACEHOLDER_DETECTED,
  },
  {
    pattern: /^(password|username|email|user|admin|root)/i,
    message: "Might be a different credential type (not a token)",
    score: RISK_WEIGHTS.WRONG_CREDENTIAL_TYPE,
  },
  {
    pattern: /\s{2,}/,
    message: "Contains multiple consecutive spaces",
    score: RISK_WEIGHTS.MULTIPLE_SPACES,
  },
  {
    pattern: /^[\s]+|[\s]+$/,
    message: "Has leading or trailing whitespace",
    score: RISK_WEIGHTS.HAS_WHITESPACE,
  },
] as const;

// ============================================================================
// TOKEN PATTERNS
// ============================================================================

/**
 * Valid token character pattern
 *
 * Most tokens consist of alphanumeric characters, underscores, hyphens, and dots.
 * Used for basic token format validation.
 */
export const VALID_TOKEN_CHARS_PATTERN = /^[A-Za-z0-9_.\-]+$/;

/**
 * Common prefix pattern for generic detection
 *
 * Matches: 2-6 lowercase letters followed by underscore
 * Examples: npm_, sk_, api_, myapp_
 */
export const GENERIC_PREFIX_PATTERN = /^[a-z]{2,6}_/;

// ============================================================================
// SEGMENT MASKING DEFAULTS
// ============================================================================

/**
 * Default delimiter for JWT mode
 */
export const DEFAULT_JWT_DELIMITER = ".";

/**
 * Default characters to show per segment in JWT mode
 */
export const DEFAULT_SEGMENT_CHARS = 3;

/**
 * Expected number of segments in a JWT
 */
export const JWT_SEGMENT_COUNT = 3;

// ============================================================================
// ERROR MESSAGES
// ============================================================================

/**
 * Standard error messages
 *
 * Centralized error messages for consistency.
 */
export const ERROR_MESSAGES = {
  EMPTY_INPUT: "Input cannot be empty",
  INVALID_MASK_CHAR: "Mask character must be a non-empty string",
  INVALID_FIXED_LENGTH: "Fixed length must be a positive number or boolean",
  INVALID_SHOW_TAIL: "showTail must be a non-negative number",
  INVALID_SHOW_HEAD: "showHead must be a non-negative number",
  INVALID_MODE: "Invalid masking mode",
  INVALID_PRESET: "Invalid preset name",
} as const;

// ============================================================================
// WARNING MESSAGES
// ============================================================================

/**
 * Standard warning message templates
 *
 * Used in validation warnings (Feature #3).
 */
export const WARNING_MESSAGES = {
  TOO_SHORT: (actual: number, expected: number) =>
    `Input too short (${actual} < ${expected})`,
  TOO_LONG: (actual: number, expected: number) =>
    `Input too long (${actual} > ${expected})`,
  HAS_WHITESPACE: "Contains whitespace (tokens typically do not)",
  MISSING_PREFIX: "Missing expected prefix pattern",
  PATTERN_MISMATCH: "Does not match expected pattern",
  CUSTOM_CHECK_FAILED: "Failed custom validation",
  LOW_ENTROPY: "Low character diversity (might not be a token)",
} as const;

// ============================================================================
// SUGGESTIONS
// ============================================================================

/**
 * Helpful suggestions for common issues
 *
 * Mapped to warning types to provide actionable guidance.
 */
export const VALIDATION_SUGGESTIONS = {
  TOO_SHORT: "Ensure you are passing the full token string",
  TOO_LONG:
    "Verify the input is a single token, not multiple concatenated values",
  HAS_WHITESPACE: "Trim whitespace from token before masking",
  MISSING_PREFIX: "Check if the token format is correct",
  PATTERN_MISMATCH: "Verify the token follows the expected format",
  CUSTOM_CHECK_FAILED: "Review custom validation logic",
  PLACEHOLDER_DETECTED: "Replace placeholder with actual token value",
  WRONG_CREDENTIAL_TYPE:
    "Ensure you are passing a token, not a password or username",
  LOW_ENTROPY: "Verify this is a real token and not a test string",
} as const;

// ============================================================================
// PACKAGE METADATA
// ============================================================================

/**
 * Package version
 *
 * Updated automatically during build/release.
 */
export const VERSION = "1.0.0";

/**
 * Package name
 */
export const PACKAGE_NAME = "mask-token";

/**
 * User agent string for logging/debugging
 */
export const USER_AGENT = `${PACKAGE_NAME}/${VERSION}`;

// ============================================================================
// FEATURE FLAGS (for future use)
// ============================================================================

/**
 * Feature flags for experimental or optional features
 *
 * Can be used to enable/disable features for testing or gradual rollout.
 */
export const FEATURE_FLAGS = {
  ENABLE_JWT_MODE: true, // JWT masking mode
  ENABLE_CUSTOM_SEGMENTS: true, // Custom segment detection
  ENABLE_VALIDATION: true, // Input validation
  ENABLE_METADATA: true, // Metadata return
  STRICT_VALIDATION: false, // Throw errors on invalid input (future)
} as const;

// ============================================================================
// TYPE EXPORTS
// ============================================================================

/**
 * Re-export commonly used types for convenience
 */
export type { MaskOptions, MaskChar, SecurityLevel } from "../types";
