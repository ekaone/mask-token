/**
 * mask-token - Secure token masking with NIST/PCI-DSS/OWASP compliance
 *
 * Type definitions for v1.0.0
 *
 * @packageDocumentation
 */

// ============================================================================
// CORE TYPES
// ============================================================================

/**
 * Security levels with predefined configurations
 *
 * - `strict`: Maximum security, minimal exposure (12 chars masked, show last 4)
 * - `balanced`: Balance between security and usability (8 chars masked, show first 2 + last 4)
 * - `lenient`: More visible for debugging (6 chars masked, show first 4 + last 6)
 * - `ui`: Optimized for UI display (8 chars masked, show first 4 + last 4)
 */
export type SecurityLevel = "strict" | "balanced" | "lenient" | "ui";

/**
 * Masking character options
 *
 * Common choices:
 * - `•` (bullet) - Default, professional appearance
 * - `*` (asterisk) - Traditional masking character
 * - `x` (multiplication) - Alternative symbol
 * - `─` (horizontal line) - Continuous appearance
 * - Custom string - Any single character or string
 */
export type MaskChar = "•" | "*" | "x" | "─" | string;

/**
 * Masking modes for special token types
 *
 * - `auto`: Automatically detect token type and apply appropriate masking
 * - `standard`: Default masking (prefix + fixed mask + tail)
 * - `jwt`: Special handling for JWT tokens (header.payload.signature)
 * - `apikey`: Standard API key masking
 * - `custom`: Custom segment-based masking
 */
export type MaskingMode = "auto" | "standard" | "jwt" | "apikey" | "custom";

// ============================================================================
// TOKEN METADATA
// ============================================================================

/**
 * Token classification from prefix detection
 *
 * Provides information about detected token type, prefix, and confidence level.
 * Used internally and optionally returned to users via `includeMetadata` option.
 *
 * @example
 * ```typescript
 * const metadata = detectTokenType('npm_abc123...');
 * // {
 * //   type: 'NPM Token',
 * //   prefix: 'npm_',
 * //   confidence: 1.0,
 * //   isLikelyToken: true
 * // }
 * ```
 */
export interface TokenMetadata {
  /**
   * Human-readable token type name
   *
   * Examples: 'NPM Token', 'GitHub Personal Access Token', 'Stripe Secret Key', 'unknown'
   */
  type: string;

  /**
   * Detected prefix string, or null if no prefix detected
   *
   * Examples: 'npm_', 'ghp_', 'sk_test_', null
   */
  prefix: string | null;

  /**
   * Confidence score for token type detection (0-1)
   *
   * - 1.0: Perfect match (known prefix, correct length)
   * - 0.9: High confidence (known prefix, length slightly off)
   * - 0.6: Medium confidence (known prefix, length very different)
   * - 0.0: No detection (unknown format)
   */
  confidence: number;

  /**
   * Whether the input looks like a valid token based on heuristics
   *
   * Checks for:
   * - Minimum length (>= 16 characters)
   * - No whitespace
   * - Valid token characters (alphanumeric, _, -)
   * - Reasonable entropy (character diversity)
   */
  isLikelyToken: boolean;
}

// ============================================================================
// VALIDATION
// ============================================================================

/**
 * Validation result for input checking
 *
 * Used to detect potential issues with input before masking,
 * such as placeholder values, wrong credential types, or suspicious patterns.
 *
 * @example
 * ```typescript
 * const result = validateToken('undefined', { minLength: 20 });
 * // {
 * //   valid: false,
 * //   warnings: ['Input too short', 'Looks like a placeholder value'],
 * //   suggestions: ['Ensure you are passing the full token string'],
 * //   riskScore: 80
 * // }
 * ```
 */
export interface ValidationResult {
  /**
   * Whether the input passed all validation checks
   */
  valid: boolean;

  /**
   * Array of warning messages for validation failures
   *
   * Examples:
   * - "Input too short (8 < 20)"
   * - "Contains whitespace (tokens typically do not)"
   * - "Looks like a placeholder value"
   */
  warnings: string[];

  /**
   * Helpful suggestions based on warnings (optional)
   *
   * Examples:
   * - "Ensure you are passing the full token string"
   * - "Trim whitespace from token before masking"
   * - "Replace placeholder with actual token value"
   */
  suggestions?: string[];

  /**
   * Risk score indicating likelihood of invalid input (0-100)
   *
   * - 0-20: Low risk (likely valid token)
   * - 21-50: Medium risk (suspicious but might be valid)
   * - 51-80: High risk (probably not a token)
   * - 81-100: Critical risk (definitely not a token)
   */
  riskScore: number;
}

/**
 * Validation rules for input checking
 *
 * Optional rules to validate input before masking.
 * Powers the `warnIfPlain` feature (Feature #3).
 */
export interface ValidationRules {
  /**
   * Minimum required length for valid tokens
   *
   * @default undefined (no minimum)
   */
  minLength?: number;

  /**
   * Maximum allowed length for valid tokens
   *
   * @default undefined (no maximum)
   */
  maxLength?: number;

  /**
   * Whether to reject inputs containing whitespace
   *
   * @default undefined (allow whitespace)
   */
  noSpaces?: boolean;

  /**
   * Whether to require a known prefix pattern
   *
   * @default undefined (prefix not required)
   */
  requirePrefix?: boolean;

  /**
   * Regular expression pattern that input must match
   *
   * @default undefined (no pattern requirement)
   */
  pattern?: RegExp;

  /**
   * Custom validation function
   *
   * @param input - The input string to validate
   * @returns true if valid, false otherwise
   *
   * @example
   * ```typescript
   * customCheck: (input) => !input.includes('test')
   * ```
   */
  customCheck?: (input: string) => boolean;
}

// ============================================================================
// MASKING OPTIONS
// ============================================================================

/**
 * Configuration for segment-based masking (JWT, custom delimiters)
 */
export interface SegmentConfig {
  /**
   * Delimiter character(s) to split segments
   *
   * @default '.' (for JWT)
   *
   * @example
   * ```typescript
   * // JWT: split by '.'
   * delimiter: '.'
   *
   * // Custom: split by '-'
   * delimiter: '-'
   * ```
   */
  delimiter?: string;

  /**
   * Number of characters to show per segment
   *
   * @default 3
   *
   * @example
   * ```typescript
   * // Show first 3 chars of each segment
   * showCharsPerSegment: 3
   * // "eyJhbGciOi..." → "eyJ•••"
   * ```
   */
  showCharsPerSegment?: number;
}

/**
 * Core masking options
 *
 * Configuration object for customizing masking behavior.
 * All options are optional - sensible defaults are applied.
 *
 * @example
 * ```typescript
 * // Minimal usage
 * maskToken('secret123')
 *
 * // With options
 * maskToken('secret123', {
 *   fixedLength: 8,
 *   showTail: 4,
 *   maskChar: '•'
 * })
 *
 * // With preset
 * maskToken('secret123', { preset: 'strict' })
 * ```
 */
export interface MaskOptions {
  // === MASKING BEHAVIOR ===

  /**
   * Use fixed-length mask to hide entropy (OWASP A02 compliance)
   *
   * - `true`: Use default fixed length (8 characters)
   * - `number`: Use specific fixed length
   * - `false`: Mask all characters between head and tail (reveals length)
   *
   * @default true
   *
   * **Security Note:** Fixed-length masking prevents length-based enumeration attacks.
   *
   * @example
   * ```typescript
   * // Fixed 8 chars (default)
   * maskToken('short', { fixedLength: true })
   * // → '••••••••ort'
   *
   * maskToken('verylongtoken', { fixedLength: true })
   * // → '••••••••ken'  (same mask length!)
   *
   * // Custom fixed length
   * maskToken('secret', { fixedLength: 12 })
   * // → '••••••••••••ret'
   *
   * // Variable length (NOT recommended for security)
   * maskToken('short', { fixedLength: false })
   * // → '••ort'
   * maskToken('verylongtoken', { fixedLength: false })
   * // → '••••••••••ken'  (different lengths!)
   * ```
   */
  fixedLength?: number | boolean;

  /**
   * Characters to show from the end (tail)
   *
   * @default 4
   *
   * @example
   * ```typescript
   * maskToken('secret123456', { showTail: 4 })
   * // → '••••••••3456'
   *
   * maskToken('secret123456', { showTail: 0 })
   * // → '••••••••••••'  (no tail visible)
   * ```
   */
  showTail?: number;

  /**
   * Characters to show from the start (head, after prefix)
   *
   * @default 0
   *
   * @example
   * ```typescript
   * maskToken('secret123456', { showHead: 2 })
   * // → 'se••••••3456'
   *
   * maskToken('npm_secret123', { showHead: 2 })
   * // → 'npm_se••••••123'  (prefix preserved separately)
   * ```
   */
  showHead?: number;

  /**
   * Character(s) used for masking
   *
   * @default '•'
   *
   * @example
   * ```typescript
   * maskToken('secret', { maskChar: '*' })
   * // → '******ret'
   *
   * maskToken('secret', { maskChar: '█' })
   * // → '██████ret'
   *
   * maskToken('secret', { maskChar: '--' })
   * // → '------------ret'
   * ```
   */
  maskChar?: MaskChar;

  // === PREFIX HANDLING ===

  /**
   * Auto-detect and preserve known prefixes (Feature #1)
   *
   * - `true`: Detect and preserve all known prefixes (npm_, ghp_, sk_, etc.)
   * - `false`: Don't preserve prefixes
   * - `string[]`: Only preserve specific prefixes
   *
   * @default true
   *
   * @example
   * ```typescript
   * // Auto-detect (default)
   * maskToken('npm_abc123xyz', { preservePrefix: true })
   * // → 'npm_••••••••xyz'
   *
   * // Disable
   * maskToken('npm_abc123xyz', { preservePrefix: false })
   * // → '••••••••••••xyz'
   *
   * // Specific prefixes only
   * maskToken('npm_abc123xyz', { preservePrefix: ['npm_', 'sk_'] })
   * // → 'npm_••••••••xyz'
   * ```
   */
  preservePrefix?: boolean | string[];

  /**
   * Custom prefix definitions (Feature #8)
   *
   * Register your own token prefixes for auto-detection.
   *
   * @example
   * ```typescript
   * maskToken('myapp_secret123', {
   *   customPrefixes: {
   *     'myapp_': 'MyApp API Key',
   *     'internal_': 'Internal Token'
   *   }
   * })
   * // → 'myapp_••••••••123'
   * ```
   */
  customPrefixes?: Record<string, string>;

  // === SECURITY & VALIDATION ===

  /**
   * Warn if input doesn't look like a token (Feature #3)
   *
   * Enables "Leaked Token Detection Hook" - warns about suspicious inputs
   * like placeholder values, passwords, or malformed tokens.
   *
   * @default false
   *
   * @example
   * ```typescript
   * maskToken('undefined', { warnIfPlain: true })
   * // Console: ⚠️ [mask-token] Looks like a placeholder value
   *
   * maskToken('my password', { warnIfPlain: true })
   * // Console: ⚠️ [mask-token] Contains whitespace (tokens typically do not)
   * ```
   */
  warnIfPlain?: boolean;

  /**
   * Custom validation rules (works with warnIfPlain)
   *
   * @example
   * ```typescript
   * maskToken(input, {
   *   warnIfPlain: true,
   *   validators: {
   *     minLength: 20,
   *     noSpaces: true,
   *     pattern: /^[A-Za-z0-9_-]+$/
   *   }
   * })
   * ```
   */
  validators?: ValidationRules;

  /**
   * Custom handler for validation warnings
   *
   * Override default console.warn behavior.
   *
   * @param result - Validation result with warnings and suggestions
   *
   * @example
   * ```typescript
   * maskToken(input, {
   *   warnIfPlain: true,
   *   onWarning: (result) => {
   *     // Send to error tracking service
   *     Sentry.captureMessage(`Invalid token: ${result.warnings.join(', ')}`);
   *
   *     // Or custom logging
   *     logger.warn('Token validation failed', {
   *       warnings: result.warnings,
   *       riskScore: result.riskScore
   *     });
   *   }
   * })
   * ```
   */
  onWarning?: (result: ValidationResult) => void;

  // === ADVANCED MODES ===

  /**
   * Special handling for specific token types
   *
   * @default 'auto'
   *
   * @example
   * ```typescript
   * // JWT mode
   * maskToken('eyJhbGc.eyJzdWI.SflKxw', { mode: 'jwt' })
   * // → 'eyJ•••.eyJ•••.Sfl•••'
   *
   * // Custom segment mode
   * maskToken('part1-part2-part3', {
   *   mode: 'custom',
   *   segments: { delimiter: '-' }
   * })
   * // → 'pa••••-pa••••-pa••••'
   * ```
   */
  mode?: MaskingMode;

  /**
   * Segment configuration for JWT/custom modes
   */
  segments?: SegmentConfig;

  // === OUTPUT CONTROL ===

  /**
   * Return metadata with masked value
   *
   * @default false
   *
   * @example
   * ```typescript
   * const result = maskToken('npm_secret123', {
   *   includeMetadata: true
   * });
   *
   * console.log(result);
   * // {
   * //   masked: 'npm_••••••••123',
   * //   metadata: { type: 'NPM Token', prefix: 'npm_', ... },
   * //   validation: { valid: true, warnings: [], ... },
   * //   original: { length: 15, hasPrefix: true }
   * // }
   * ```
   */
  includeMetadata?: boolean;

  /**
   * Security preset (overrides individual options)
   *
   * Using a preset overrides conflicting individual options.
   *
   * @example
   * ```typescript
   * maskToken('secret', { preset: 'strict' })
   * // Equivalent to:
   * // {
   * //   fixedLength: 12,
   * //   showTail: 4,
   * //   showHead: 0,
   * //   maskChar: '•',
   * //   preservePrefix: true,
   * //   warnIfPlain: true
   * // }
   * ```
   */
  preset?: SecurityLevel;
}

// ============================================================================
// RESULT TYPES
// ============================================================================

/**
 * Complete result object when includeMetadata is true
 *
 * @example
 * ```typescript
 * const result = maskToken('npm_secret123', { includeMetadata: true });
 *
 * console.log(result.masked);           // 'npm_••••••••123'
 * console.log(result.metadata.type);    // 'NPM Token'
 * console.log(result.validation.valid); // true
 * console.log(result.original.length);  // 15
 * ```
 */
export interface MaskResult {
  /**
   * The masked token string
   */
  masked: string;

  /**
   * Detected token metadata (type, prefix, confidence)
   */
  metadata: TokenMetadata;

  /**
   * Validation result (warnings, risk score)
   */
  validation: ValidationResult;

  /**
   * Original token information (without exposing the token itself)
   */
  original: {
    /**
     * Length of original token
     */
    length: number;

    /**
     * Whether a prefix was detected
     */
    hasPrefix: boolean;
  };
}

// ============================================================================
// PRESET CONFIGURATION
// ============================================================================

/**
 * Preset configuration for definePreset()
 *
 * Combines MaskOptions with metadata about the preset.
 *
 * @example
 * ```typescript
 * const myPreset: PresetConfig = {
 *   name: 'corporate',
 *   description: 'Corporate security policy compliant',
 *   fixedLength: 16,
 *   showTail: 6,
 *   maskChar: '█',
 *   warnIfPlain: true,
 *   validators: { minLength: 32 }
 * };
 *
 * const mask = definePreset(myPreset);
 * mask('secret'); // Uses corporate preset
 * ```
 */
export interface PresetConfig extends MaskOptions {
  /**
   * Preset name (for debugging/logging)
   */
  name: string;

  /**
   * Human-readable description of the preset
   */
  description?: string;
}

// ============================================================================
// PREFIX DEFINITION (Internal)
// ============================================================================

/**
 * Internal type for known prefix definitions
 *
 * @internal
 */
export interface PrefixDefinition {
  /**
   * Prefix pattern (string or regex)
   */
  pattern: string | RegExp;

  /**
   * Human-readable name
   */
  name: string;

  /**
   * Minimum expected token length (optional)
   */
  minLength?: number;

  /**
   * Token category (optional)
   */
  category?: "api" | "oauth" | "secret" | "key";
}

// ============================================================================
// TYPE GUARDS
// ============================================================================

/**
 * Type guard to check if a value is a MaskResult
 *
 * @param value - Value to check
 * @returns true if value is a MaskResult
 *
 * @example
 * ```typescript
 * const result = maskToken(token, { includeMetadata: true });
 *
 * if (isMaskResult(result)) {
 *   console.log(result.metadata.type);
 * } else {
 *   console.log(result); // Just a string
 * }
 * ```
 */
export function isMaskResult(value: unknown): value is MaskResult {
  return (
    typeof value === "object" &&
    value !== null &&
    "masked" in value &&
    "metadata" in value &&
    "validation" in value &&
    "original" in value
  );
}

/**
 * Type guard to check if a value is a valid MaskChar
 *
 * @param value - Value to check
 * @returns true if value is a valid MaskChar
 */
export function isMaskChar(value: unknown): value is MaskChar {
  return typeof value === "string" && value.length >= 1;
}

/**
 * Type guard to check if a value is a SecurityLevel
 *
 * @param value - Value to check
 * @returns true if value is a valid SecurityLevel
 */
export function isSecurityLevel(value: unknown): value is SecurityLevel {
  return (
    typeof value === "string" &&
    ["strict", "balanced", "lenient", "ui"].includes(value)
  );
}
