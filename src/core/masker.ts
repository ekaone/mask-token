/**
 * mask-token - Secure token masking with NIST/PCI-DSS/OWASP compliance
 *
 * Core masking algorithm
 *
 * Features:
 * - #2: Entropy-Safe Fixed Length Masking
 * - #5: Custom Mask Characters
 * - #6: Configurable Head/Tail
 *
 * @module core/masker
 */

import type { MaskOptions, MaskResult, TokenMetadata } from "../types";
import { detectPrefix } from "../presets/registry";
import { validateInput } from "./validator";
import { getPreset } from "../presets/defaults";
import {
  DEFAULT_OPTIONS,
  DEFAULT_JWT_DELIMITER,
  DEFAULT_SEGMENT_CHARS,
  JWT_SEGMENT_COUNT,
} from "../utils/constants";

// ============================================================================
// MAIN MASKING FUNCTION
// ============================================================================

/**
 * Mask a token with security-first defaults
 *
 * This is the core masking function that orchestrates the entire process:
 * 1. Merge options with defaults or preset
 * 2. Validate input (if warnIfPlain enabled)
 * 3. Detect token type and prefix
 * 4. Route to appropriate masking strategy
 * 5. Return masked string or full result
 *
 * @param input - Token string to mask
 * @param options - Masking configuration options
 * @returns Masked string, or MaskResult if includeMetadata is true
 *
 * @example
 * ```typescript
 * // Basic usage (uses defaults)
 * mask('npm_a1b2c3d4e5f6g7h8i9j0');
 * // → 'npm_••••••••i9j0'
 *
 * // With custom options
 * mask('sk_test_abc123xyz', {
 *   fixedLength: 12,
 *   showTail: 6,
 *   maskChar: '*'
 * });
 * // → 'sk_test_************123xyz'
 *
 * // With preset
 * mask('ghp_abc123xyz', { preset: 'strict' });
 * // → 'ghp_••••••••••••xyz'
 *
 * // With metadata
 * const result = mask('npm_secret123', { includeMetadata: true });
 * // → {
 * //     masked: 'npm_••••••••t123',
 * //     metadata: { type: 'NPM Token', prefix: 'npm_', ... },
 * //     validation: { valid: true, warnings: [], ... },
 * //     original: { length: 17, hasPrefix: true }
 * //   }
 * ```
 */
export function mask(
  input: string,
  options: MaskOptions = {},
): string | MaskResult {
  // ============================================================================
  // 1. MERGE OPTIONS WITH DEFAULTS OR PRESET
  // ============================================================================

  let opts: Required<MaskOptions>;

  if (options.preset) {
    // Use preset as base, then apply overrides
    const presetConfig = getPreset(options.preset);
    if (!presetConfig) {
      throw new Error(`Unknown preset: ${options.preset}`);
    }

    opts = mergeWithDefaults({
      ...presetConfig,
      ...options,
      // Merge validators if both exist
      validators: options.validators
        ? { ...presetConfig.validators, ...options.validators }
        : presetConfig.validators,
    });
  } else {
    // Use defaults
    opts = mergeWithDefaults(options);
  }

  // ============================================================================
  // 2. VALIDATE INPUT (if enabled)
  // ============================================================================

  const validation = opts.warnIfPlain
    ? validateInput(input, opts.validators)
    : { valid: true, warnings: [], riskScore: 0 };

  if (opts.warnIfPlain && !validation.valid) {
    // Trigger warning callback or default console.warn
    if (opts.onWarning) {
      opts.onWarning(validation);
    } else {
      console.warn(`[mask-token] ${validation.warnings.join(", ")}`);
      if (validation.suggestions && validation.suggestions.length > 0) {
        console.warn(
          `[mask-token] Suggestions: ${validation.suggestions.join(", ")}`,
        );
      }
    }
  }

  // ============================================================================
  // 3. DETECT TOKEN TYPE & PREFIX
  // ============================================================================

  const metadata = detectPrefix(input, opts.customPrefixes);

  // ============================================================================
  // 4. ROUTE TO APPROPRIATE MASKING STRATEGY
  // ============================================================================

  let masked: string;

  switch (opts.mode) {
    case "jwt":
      masked = maskJWT(input, opts);
      break;

    case "custom":
      masked = maskCustomSegments(input, opts);
      break;

    case "apikey":
    case "standard":
    case "auto":
    default:
      masked = maskStandard(input, metadata, opts);
      break;
  }

  // ============================================================================
  // 5. RETURN RESULT
  // ============================================================================

  if (opts.includeMetadata) {
    return {
      masked,
      metadata,
      validation,
      original: {
        length: input.length,
        hasPrefix: metadata.prefix !== null,
      },
    };
  }

  return masked;
}

// ============================================================================
// MASKING STRATEGIES
// ============================================================================

/**
 * Standard masking algorithm
 *
 * This is the core masking logic that implements:
 * - Feature #1: Prefix preservation
 * - Feature #2: Entropy-safe fixed-length masking
 * - Feature #5: Custom mask characters
 * - Feature #6: Configurable head/tail
 *
 * Algorithm:
 * 1. Extract prefix (if preservePrefix enabled and prefix detected)
 * 2. Calculate head characters to show
 * 3. Calculate tail characters to show
 * 4. Generate fixed-length mask (or variable if fixedLength=false)
 * 5. Combine: prefix + head + mask + tail
 *
 * @param input - Token string
 * @param metadata - Token metadata from prefix detection
 * @param opts - Masking options
 * @returns Masked string
 *
 * @internal
 */
function maskStandard(
  input: string,
  metadata: TokenMetadata,
  opts: Required<MaskOptions>,
): string {
  // Step 1: Separate prefix from secret
  let prefix = "";
  let secret = input;

  if (opts.preservePrefix && metadata.prefix) {
    // Handle boolean or array of specific prefixes
    if (
      opts.preservePrefix === true ||
      (Array.isArray(opts.preservePrefix) &&
        opts.preservePrefix.includes(metadata.prefix))
    ) {
      prefix = metadata.prefix;
      secret = input.slice(metadata.prefix.length);
    }
  }

  // Handle edge case: secret is empty or very short
  if (secret.length === 0) {
    return prefix; // Just return prefix
  }

  // Step 2: Security Check - Prevent full secret exposure
  // CRITICAL: Ensure head + tail never expose the entire secret
  // This prevents security vulnerabilities where short tokens become fully unmasked
  
  let headChars = Math.min(opts.showHead, secret.length);
  let tailChars = Math.min(opts.showTail, secret.length);
  
  // Calculate minimum characters that MUST be masked
  const minMaskChars = 1; // At least 1 character must always be masked
  
  // Check for overlap condition
  if (headChars + tailChars >= secret.length) {
    // SECURITY FIX: Adjust visible characters to ensure masking
    const maxVisibleChars = Math.max(0, secret.length - minMaskChars);
    
    if (maxVisibleChars === 0) {
      // Secret is too short (1 char) - mask everything
      const fixedMaskLength =
        typeof opts.fixedLength === "number" ? opts.fixedLength : 8;
      return prefix + opts.maskChar.repeat(fixedMaskLength);
    }
    
    // Distribute visible characters between head and tail
    // Priority: tail gets preference (more useful for identification)
    const adjustedTail = Math.min(tailChars, Math.floor(maxVisibleChars / 2));
    const adjustedHead = Math.min(headChars, maxVisibleChars - adjustedTail);
    
    // Log warning about auto-adjustment
    if (opts.warnIfPlain) {
      console.warn(
        `[mask-token] SECURITY: Adjusted showHead (${opts.showHead}→${adjustedHead}) ` +
        `and showTail (${opts.showTail}→${adjustedTail}) to prevent full secret exposure ` +
        `(secret length: ${secret.length})`
      );
    }
    
    headChars = adjustedHead;
    tailChars = adjustedTail;
  }
  
  // Step 3: Extract head and tail
  const head = secret.slice(0, headChars);
  const tail = tailChars > 0 ? secret.slice(-tailChars) : "";

  // Step 4: Generate mask
  let mask: string;

  if (opts.fixedLength === false) {
    // Variable-length masking (NOT recommended for security)
    const maskLength = Math.max(minMaskChars, secret.length - headChars - tailChars);
    mask = opts.maskChar.repeat(maskLength);
  } else {
    // Fixed-length masking (RECOMMENDED - entropy-safe)
    const fixedMaskLength =
      typeof opts.fixedLength === "number" ? opts.fixedLength : 8; // Default to 8 if true

    mask = opts.maskChar.repeat(fixedMaskLength);
  }

  // Step 5: Combine components
  return prefix + head + mask + tail;
}

/**
 * JWT-specific masking (header.payload.signature)
 *
 * Special handling for JWT tokens which have three dot-separated segments.
 * Masks each segment independently while preserving the dot separators.
 *
 * @param input - JWT token string
 * @param opts - Masking options
 * @returns Masked JWT string
 *
 * @example
 * ```typescript
 * maskJWT('eyJhbGciOi.eyJzdWIiOi.SflKxwRJ', options);
 * // → 'eyJ•••.eyJ•••.Sfl•••'
 * ```
 *
 * @internal
 */
function maskJWT(input: string, opts: Required<MaskOptions>): string {
  const delimiter = opts.segments?.delimiter ?? DEFAULT_JWT_DELIMITER;
  const parts = input.split(delimiter);

  // Validate JWT structure (should have 3 parts)
  if (parts.length !== JWT_SEGMENT_COUNT) {
    // Not a valid JWT, fall back to standard masking
    console.warn(
      `[mask-token] JWT mode expects ${JWT_SEGMENT_COUNT} segments, found ${parts.length}. Falling back to standard masking.`,
    );
    return maskStandard(input, detectPrefix(input), opts);
  }

  const charsPerSegment =
    opts.segments?.showCharsPerSegment ?? DEFAULT_SEGMENT_CHARS;

  // Mask each segment
  const maskedParts = parts.map((part) => {
    if (part.length <= charsPerSegment) {
      // Segment too short to mask
      return part;
    }

    const head = part.slice(0, charsPerSegment);
    const mask = opts.maskChar.repeat(3); // Fixed 3 chars for JWT

    return head + mask;
  });

  return maskedParts.join(delimiter);
}

/**
 * Custom segment-based masking
 *
 * Splits input by custom delimiter and masks each segment.
 * Useful for tokens with hyphen/dash separators.
 *
 * @param input - Token string
 * @param opts - Masking options with segment configuration
 * @returns Masked string
 *
 * @example
 * ```typescript
 * maskCustomSegments('part1-part2-part3', {
 *   segments: { delimiter: '-', showCharsPerSegment: 2 }
 * });
 * // → 'pa••••-pa••••-pa••••'
 * ```
 *
 * @internal
 */
function maskCustomSegments(
  input: string,
  opts: Required<MaskOptions>,
): string {
  const delimiter = opts.segments?.delimiter ?? "-";
  const parts = input.split(delimiter);
  const charsPerSegment = opts.segments?.showCharsPerSegment ?? 2;

  // Mask each segment
  const maskedParts = parts.map((part) => {
    if (part.length <= charsPerSegment * 2) {
      // Segment too short to mask meaningfully
      return part;
    }

    const head = part.slice(0, charsPerSegment);
    const tail = part.slice(-charsPerSegment);
    const mask = opts.maskChar.repeat(4); // Fixed 4 chars

    return head + mask + tail;
  });

  return maskedParts.join(delimiter);
}

// ============================================================================
// OPTIONS UTILITIES
// ============================================================================

/**
 * Merge user options with defaults
 *
 * Ensures all required options have values.
 *
 * @param options - User-provided options
 * @returns Complete options object with defaults filled in
 *
 * @internal
 */
function mergeWithDefaults(options: MaskOptions): Required<MaskOptions> {
  return {
    // Use user values or defaults
    fixedLength: options.fixedLength ?? DEFAULT_OPTIONS.fixedLength,
    showTail: options.showTail ?? DEFAULT_OPTIONS.showTail,
    showHead: options.showHead ?? DEFAULT_OPTIONS.showHead,
    maskChar: options.maskChar ?? DEFAULT_OPTIONS.maskChar,
    preservePrefix: options.preservePrefix ?? DEFAULT_OPTIONS.preservePrefix,
    warnIfPlain: options.warnIfPlain ?? DEFAULT_OPTIONS.warnIfPlain,
    mode: options.mode ?? DEFAULT_OPTIONS.mode,
    includeMetadata: options.includeMetadata ?? DEFAULT_OPTIONS.includeMetadata,

    // Optional fields (provide empty defaults)
    customPrefixes: options.customPrefixes ?? {},
    validators: options.validators,
    segments: options.segments,
    onWarning: options.onWarning,
    preset: options.preset,
  } as Required<MaskOptions>;
}

// ============================================================================
// CONVENIENCE FUNCTIONS
// ============================================================================

/**
 * Mask with strict preset (shorthand)
 *
 * @param input - Token to mask
 * @returns Masked token
 *
 * @example
 * ```typescript
 * maskStrict('npm_abc123xyz');
 * // → 'npm_••••••••••••xyz'
 * ```
 */
export function maskStrict(input: string): string {
  return mask(input, { preset: "strict" }) as string;
}

/**
 * Mask with balanced preset (shorthand)
 *
 * @param input - Token to mask
 * @returns Masked token
 *
 * @example
 * ```typescript
 * maskBalanced('npm_abc123xyz');
 * // → 'npm_ab••••••••xyz'
 * ```
 */
export function maskBalanced(input: string): string {
  return mask(input, { preset: "balanced" }) as string;
}

/**
 * Mask with lenient preset (shorthand)
 *
 * @param input - Token to mask
 * @returns Masked token
 *
 * @example
 * ```typescript
 * maskLenient('npm_abc123xyz');
 * // → 'npm_abcd******23xyz'
 * ```
 */
export function maskLenient(input: string): string {
  return mask(input, { preset: "lenient" }) as string;
}

/**
 * Mask with UI preset (shorthand)
 *
 * @param input - Token to mask
 * @returns Masked token
 *
 * @example
 * ```typescript
 * maskUI('npm_abc123xyz');
 * // → 'npm_abcd••••••3xyz'
 * ```
 */
export function maskUI(input: string): string {
  return mask(input, { preset: "ui" }) as string;
}

/**
 * Mask multiple tokens at once
 *
 * @param inputs - Array of tokens to mask
 * @param options - Masking options (applied to all tokens)
 * @returns Array of masked tokens
 *
 * @example
 * ```typescript
 * maskBatch(['npm_abc123', 'ghp_xyz789'], { preset: 'strict' });
 * // → ['npm_••••••••••••123', 'ghp_••••••••••••789']
 * ```
 */
export function maskBatch(inputs: string[], options?: MaskOptions): string[] {
  return inputs.map((input) => mask(input, options) as string);
}
