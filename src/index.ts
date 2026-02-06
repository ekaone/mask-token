/**
 * mask-token - Secure token masking with NIST/PCI-DSS/OWASP compliance
 *
 * Main entry point
 *
 * @packageDocumentation
 *
 * @example
 * ```typescript
 * import { maskToken } from 'mask-token';
 *
 * // Basic usage
 * const masked = maskToken('npm_a1b2c3d4e5f6g7h8i9j0');
 * console.log(masked); // → 'npm_••••••••i9j0'
 *
 * // With options
 * const masked = maskToken('sk_test_abc123xyz', {
 *   fixedLength: 12,
 *   showTail: 6,
 *   maskChar: '*'
 * });
 *
 * // With preset
 * import { presets } from 'mask-token';
 * const masked = presets.strict('secret123');
 * ```
 */

// ============================================================================
// CORE EXPORTS
// ============================================================================

import { mask } from "./core/masker";
import type { MaskOptions, MaskResult, PresetConfig } from "./types";

/**
 * Mask a token with security-first defaults
 *
 * This is the main function of the package. It provides intelligent
 * token masking with automatic prefix detection, entropy-safe fixed-length
 * masking, and optional input validation.
 *
 * @param token - Token string to mask
 * @param options - Optional masking configuration
 * @returns Masked string, or MaskResult object if includeMetadata is true
 *
 * @example
 * ```typescript
 * // Basic usage (auto-detects NPM token)
 * maskToken('npm_a1b2c3d4e5f6g7h8i9j0');
 * // → 'npm_••••••••i9j0'
 *
 * // GitHub token (auto-detected)
 * maskToken('ghp_abcdefghijklmnopqrstuvwxyz123456');
 * // → 'ghp_••••••••3456'
 *
 * // Stripe secret key (auto-detected)
 * maskToken('sk_test_1234567890abcdefghijklmn');
 * // → 'sk_test_••••••••klmn'
 *
 * // Custom options
 * maskToken('secret123', {
 *   fixedLength: 6,
 *   showTail: 3,
 *   maskChar: '*'
 * });
 * // → '******123'
 *
 * // With preset
 * maskToken('token123', { preset: 'strict' });
 * // → '••••••••••••123'
 *
 * // With validation
 * maskToken('undefined', { warnIfPlain: true });
 * // Console warning: "Looks like a placeholder value"
 * // → '••••••••ned'
 *
 * // Get metadata
 * const result = maskToken('npm_secret123', { includeMetadata: true });
 * console.log(result.metadata.type); // → 'NPM Token'
 * console.log(result.masked);        // → 'npm_••••••••t123'
 * ```
 */
export function maskToken(token: string): string;
export function maskToken(
  token: string,
  options: MaskOptions & { includeMetadata: true },
): MaskResult;
export function maskToken(token: string, options: MaskOptions): string;
export function maskToken(
  token: string,
  options?: MaskOptions,
): string | MaskResult {
  return mask(token, options);
}

// ============================================================================
// PRESET FUNCTIONS
// ============================================================================

import {
  PRESET_STRICT,
  PRESET_BALANCED,
  PRESET_LENIENT,
  PRESET_UI,
  getPreset,
} from "./presets/defaults";

/**
 * Built-in security presets
 *
 * Pre-configured masking profiles optimized for different use cases.
 *
 * - `strict`: Maximum security for production/compliance
 * - `balanced`: Good balance for general use
 * - `lenient`: More visible for development/debugging
 * - `ui`: Optimized for user interface display
 *
 * @example
 * ```typescript
 * import { presets } from 'mask-token';
 *
 * // Use strict preset (production)
 * presets.strict('sk_test_abc123xyz');
 * // → 'sk_test_••••••••••••xyz'
 *
 * // Use balanced preset (general)
 * presets.balanced('sk_test_abc123xyz');
 * // → 'sk_test_ab••••••••xyz'
 *
 * // Use lenient preset (development)
 * presets.lenient('sk_test_abc123xyz');
 * // → 'sk_test_abcd******23xyz'
 *
 * // Use UI preset (user interfaces)
 * presets.ui('sk_test_abc123xyz');
 * // → 'sk_test_abcd••••••3xyz'
 * ```
 */
export const presets = {
  /**
   * Strict security preset
   *
   * - Fixed 12-char mask
   * - Show last 4 chars only
   * - Validation enabled
   * - Best for: Production logs, compliance, audit trails
   */
  strict: (token: string) => mask(token, PRESET_STRICT) as string,

  /**
   * Balanced security preset
   *
   * - Fixed 8-char mask
   * - Show first 2 + last 4 chars
   * - Validation enabled
   * - Best for: General use, developer tools, dashboards
   */
  balanced: (token: string) => mask(token, PRESET_BALANCED) as string,

  /**
   * Lenient security preset
   *
   * - Fixed 6-char mask
   * - Show first 4 + last 6 chars
   * - No validation
   * - Best for: Development, debugging (NOT production)
   */
  lenient: (token: string) => mask(token, PRESET_LENIENT) as string,

  /**
   * UI-optimized preset
   *
   * - Fixed 8-char mask
   * - Show first 4 + last 4 chars (symmetric)
   * - No validation
   * - Best for: Settings pages, dashboards, mobile apps
   */
  ui: (token: string) => mask(token, PRESET_UI) as string,
} as const;

/**
 * Create a custom reusable preset
 *
 * Define your own masking configuration and use it like built-in presets.
 *
 * @param config - Preset configuration with name and options
 * @returns Function that applies the preset
 *
 * @example
 * ```typescript
 * import { definePreset } from 'mask-token';
 *
 * // Create custom preset
 * const myPreset = definePreset({
 *   name: 'corporate',
 *   description: 'Corporate security policy',
 *   fixedLength: 16,
 *   showTail: 6,
 *   maskChar: '█',
 *   warnIfPlain: true
 * });
 *
 * // Use it
 * const masked = myPreset('secret123');
 * ```
 */
export function definePreset(config: PresetConfig): (token: string) => string {
  return (token: string) => mask(token, config) as string;
}

// ============================================================================
// PREFIX DETECTION & MANAGEMENT
// ============================================================================

import {
  registerPrefix,
  detectPrefix,
  isLikelyTokenHeuristic,
  getSupportedPrefixes,
  getPrefixCount,
} from "./presets/registry";

export {
  /**
   * Register a custom token prefix for auto-detection
   *
   * @param prefix - Prefix string (e.g., 'myapp_')
   * @param description - Human-readable name (e.g., 'MyApp API Key')
   *
   * @example
   * ```typescript
   * import { registerPrefix, maskToken } from 'mask-token';
   *
   * // Register custom prefix
   * registerPrefix('myapp_', 'MyApp API Key');
   *
   * // Now it's auto-detected
   * maskToken('myapp_secret123');
   * // → 'myapp_••••••••123'
   * ```
   */
  registerPrefix,

  /**
   * Detect token type from input
   *
   * @param input - Token string
   * @returns Token metadata (type, prefix, confidence)
   *
   * @example
   * ```typescript
   * import { detectTokenType } from 'mask-token';
   *
   * const metadata = detectTokenType('npm_abc123');
   * console.log(metadata);
   * // {
   * //   type: 'NPM Token',
   * //   prefix: 'npm_',
   * //   confidence: 1.0,
   * //   isLikelyToken: true
   * // }
   * ```
   */
  detectPrefix as detectTokenType,

  /**
   * Check if string looks like a token (heuristic)
   *
   * @param input - String to check
   * @returns true if input has token-like characteristics
   *
   * @example
   * ```typescript
   * import { isLikelyToken } from 'mask-token';
   *
   * isLikelyToken('abcdef1234567890');  // true
   * isLikelyToken('hello world');       // false (whitespace)
   * isLikelyToken('short');             // false (too short)
   * ```
   */
  isLikelyTokenHeuristic as isLikelyToken,

  /**
   * Get list of all supported token types
   *
   * @returns Array of token type names
   *
   * @example
   * ```typescript
   * import { getSupportedTokenTypes } from 'mask-token';
   *
   * const types = getSupportedTokenTypes();
   * console.log(types);
   * // ['NPM Token', 'GitHub Personal Access Token', 'Stripe Secret Key', ...]
   * ```
   */
  getSupportedPrefixes as getSupportedTokenTypes,

  /**
   * Get count of registered prefixes
   *
   * @returns Object with total, custom, builtin, and by-category counts
   *
   * @example
   * ```typescript
   * import { getPrefixCount } from 'mask-token';
   *
   * const count = getPrefixCount();
   * console.log(count);
   * // {
   * //   total: 43,
   * //   custom: 0,
   * //   builtin: 43,
   * //   byCategory: { api: 25, oauth: 12, secret: 6, key: 2 }
   * // }
   * ```
   */
  getPrefixCount,
};

// ============================================================================
// VALIDATION
// ============================================================================

import { validateInput, isLikelyValid } from "./core/validator";

export {
  /**
   * Validate token input
   *
   * @param input - String to validate
   * @param rules - Optional validation rules
   * @returns Validation result with warnings and risk score
   *
   * @example
   * ```typescript
   * import { validateToken } from 'mask-token';
   *
   * const result = validateToken('undefined', {
   *   minLength: 20,
   *   noSpaces: true
   * });
   *
   * console.log(result);
   * // {
   * //   valid: false,
   * //   warnings: ['Input too short', 'Looks like a placeholder'],
   * //   suggestions: ['Ensure you are passing the full token string'],
   * //   riskScore: 80
   * // }
   * ```
   */
  validateInput as validateToken,

  /**
   * Quick check if input is likely valid
   *
   * @param input - String to check
   * @returns true if risk score is low/medium
   *
   * @example
   * ```typescript
   * import { isLikelyValid } from 'mask-token';
   *
   * isLikelyValid('npm_abc123xyz');  // true
   * isLikelyValid('undefined');      // false
   * ```
   */
  isLikelyValid,
};

// ============================================================================
// TYPE EXPORTS
// ============================================================================

export type {
  // Core types
  MaskOptions,
  MaskResult,
  MaskChar,
  SecurityLevel,
  MaskingMode,

  // Metadata
  TokenMetadata,

  // Validation
  ValidationResult,
  ValidationRules,

  // Configuration
  PresetConfig,
  SegmentConfig,
} from "./types";

// ============================================================================
// CONSTANTS & VERSION
// ============================================================================

import { VERSION, PACKAGE_NAME } from "./utils/constants";

export {
  /**
   * Package version
   *
   * @example
   * ```typescript
   * import { VERSION } from 'mask-token';
   * console.log(VERSION); // '1.0.0'
   * ```
   */
  VERSION,

  /**
   * Package name
   *
   * @example
   * ```typescript
   * import { PACKAGE_NAME } from 'mask-token';
   * console.log(PACKAGE_NAME); // 'mask-token'
   * ```
   */
  PACKAGE_NAME,
};

// ============================================================================
// DEFAULT EXPORT
// ============================================================================

/**
 * Default export (same as named export maskToken)
 *
 * @example
 * ```typescript
 * // Named import (recommended)
 * import { maskToken } from 'mask-token';
 *
 * // Default import
 * import maskToken from 'mask-token';
 *
 * // Both work the same
 * maskToken('npm_secret123');
 * ```
 */
export default maskToken;
