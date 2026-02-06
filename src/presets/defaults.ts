/**
 * mask-token - Secure token masking with NIST/PCI-DSS/OWASP compliance
 *
 * Built-in preset configurations
 *
 * Feature #7: Built-in Presets
 *
 * @module presets/defaults
 */

import type { PresetConfig, MaskOptions } from "../types";

// ============================================================================
// PRESET: STRICT
// ============================================================================

/**
 * Strict security preset
 *
 * Maximum security with minimal exposure. Recommended for:
 * - Production logs
 * - Compliance-heavy environments (PCI-DSS, SOC2, HIPAA)
 * - Public-facing displays
 * - Security audit trails
 *
 * Configuration:
 * - Fixed 12-character mask (hides maximum entropy)
 * - Show last 4 characters only (no head visible)
 * - Prefix preservation enabled (context without exposure)
 * - Validation warnings enabled (catch mistakes early)
 * - Bullet character (•) for professional appearance
 *
 * @example
 * ```typescript
 * import { presets } from 'mask-token';
 *
 * presets.strict('sk_test_1234567890abcdefghijklmn');
 * // → 'sk_test_••••••••••••klmn'
 *
 * presets.strict('npm_a1b2c3d4e5f6g7h8i9j0');
 * // → 'npm_••••••••••••i9j0'
 * ```
 */
export const PRESET_STRICT: PresetConfig = {
  name: "strict",
  description: "Maximum security - minimal exposure (PCI-DSS/SOC2 compliant)",

  // Masking behavior
  fixedLength: 12, // Long fixed mask (entropy-safe)
  showTail: 4, // Only last 4 chars visible
  showHead: 0, // No head chars (maximum security)
  maskChar: "•", // Professional bullet character

  // Prefix handling
  preservePrefix: true, // Auto-detect and preserve context

  // Security features
  warnIfPlain: true, // Warn about suspicious inputs
  validators: {
    minLength: 16, // Enforce minimum token length
    noSpaces: true, // Reject inputs with whitespace
  },

  // Mode
  mode: "auto", // Auto-detect token type
};

// ============================================================================
// PRESET: BALANCED
// ============================================================================

/**
 * Balanced security preset
 *
 * Good balance between security and usability. Recommended for:
 * - General application use
 * - Developer tools
 * - Internal dashboards
 * - API documentation
 *
 * Configuration:
 * - Fixed 8-character mask (entropy-safe, standard length)
 * - Show first 2 + last 4 characters (easier identification)
 * - Prefix preservation enabled
 * - Validation warnings enabled
 * - Bullet character (•)
 *
 * @example
 * ```typescript
 * import { presets } from 'mask-token';
 *
 * presets.balanced('sk_test_1234567890abcdefghijklmn');
 * // → 'sk_test_12••••••••klmn'
 *
 * presets.balanced('ghp_a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6');
 * // → 'ghp_a1••••••••o5p6'
 * ```
 */
export const PRESET_BALANCED: PresetConfig = {
  name: "balanced",
  description: "Balance security and usability - good for general use",

  // Masking behavior
  fixedLength: 8, // Standard fixed mask length
  showTail: 4, // Last 4 chars (industry standard)
  showHead: 2, // First 2 chars (after prefix)
  maskChar: "•", // Professional bullet character

  // Prefix handling
  preservePrefix: true, // Auto-detect and preserve context

  // Security features
  warnIfPlain: true, // Warn about suspicious inputs
  validators: {
    minLength: 12, // Slightly relaxed minimum
    noSpaces: true, // Reject whitespace
  },

  // Mode
  mode: "auto", // Auto-detect token type
};

// ============================================================================
// PRESET: LENIENT
// ============================================================================

/**
 * Lenient security preset
 *
 * More visible for debugging and development. Recommended for:
 * - Development environments only
 * - Debugging sessions
 * - Local testing
 * - Developer logs (non-production)
 *
 * ⚠️ WARNING: Not recommended for production use
 *
 * Configuration:
 * - Fixed 6-character mask (shorter, more visible)
 * - Show first 4 + last 6 characters
 * - Prefix preservation enabled
 * - No validation warnings (less strict)
 * - Asterisk character (*) for traditional appearance
 *
 * @example
 * ```typescript
 * import { presets } from 'mask-token';
 *
 * presets.lenient('sk_test_1234567890abcdefghijklmn');
 * // → 'sk_test_1234******ijklmn'
 *
 * presets.lenient('ghp_a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6');
 * // → 'ghp_a1b2******n4o5p6'
 * ```
 */
export const PRESET_LENIENT: PresetConfig = {
  name: "lenient",
  description: "More visible for debugging - use in development only",

  // Masking behavior
  fixedLength: 6, // Shorter mask (more visible)
  showTail: 6, // More tail chars visible
  showHead: 4, // More head chars visible
  maskChar: "*", // Traditional asterisk (less formal)

  // Prefix handling
  preservePrefix: true, // Auto-detect and preserve context

  // Security features
  warnIfPlain: false, // No warnings (development mode)
  validators: undefined, // No strict validation

  // Mode
  mode: "auto", // Auto-detect token type
};

// ============================================================================
// PRESET: UI
// ============================================================================

/**
 * UI-optimized preset
 *
 * Optimized for user interface display. Recommended for:
 * - Settings pages
 * - Account dashboards
 * - Token management UIs
 * - Mobile applications
 *
 * Configuration:
 * - Fixed 8-character mask (standard, clean appearance)
 * - Show first 4 + last 4 characters (symmetric, easy to read)
 * - Prefix preservation enabled
 * - No validation warnings (user-facing, less technical)
 * - Bullet character (•) for clean UI appearance
 *
 * @example
 * ```typescript
 * import { presets } from 'mask-token';
 *
 * presets.ui('sk_test_1234567890abcdefghijklmn');
 * // → 'sk_test_1234••••••••klmn'
 *
 * presets.ui('npm_a1b2c3d4e5f6g7h8i9j0');
 * // → 'npm_a1b2••••••••i9j0'
 * ```
 */
export const PRESET_UI: PresetConfig = {
  name: "ui",
  description: "Optimized for UI display - clean and readable",

  // Masking behavior
  fixedLength: 8, // Standard fixed mask
  showTail: 4, // Symmetric with showHead
  showHead: 4, // Symmetric with showTail
  maskChar: "•", // Clean bullet for UI

  // Prefix handling
  preservePrefix: true, // Auto-detect and preserve context

  // Security features
  warnIfPlain: false, // No warnings in UI (less technical)
  validators: undefined, // No strict validation

  // Mode
  mode: "auto", // Auto-detect token type
};

// ============================================================================
// PRESET COLLECTION
// ============================================================================

/**
 * Collection of all built-in presets
 *
 * Exported as a convenience object for easy access.
 *
 * @example
 * ```typescript
 * import { PRESETS } from 'mask-token/presets';
 *
 * // Access by name
 * const strictConfig = PRESETS.strict;
 * const balancedConfig = PRESETS.balanced;
 *
 * // Iterate over all presets
 * Object.entries(PRESETS).forEach(([name, config]) => {
 *   console.log(`${name}: ${config.description}`);
 * });
 * ```
 */
export const PRESETS = {
  strict: PRESET_STRICT,
  balanced: PRESET_BALANCED,
  lenient: PRESET_LENIENT,
  ui: PRESET_UI,
} as const;

// ============================================================================
// PRESET UTILITIES
// ============================================================================

/**
 * Get preset configuration by name
 *
 * @param name - Preset name ('strict' | 'balanced' | 'lenient' | 'ui')
 * @returns Preset configuration or undefined if not found
 *
 * @example
 * ```typescript
 * const config = getPreset('strict');
 * if (config) {
 *   console.log(config.description);
 *   console.log(config.fixedLength); // 12
 * }
 * ```
 */
export function getPreset(name: string): PresetConfig | undefined {
  return PRESETS[name as keyof typeof PRESETS];
}

/**
 * Check if a preset name is valid
 *
 * @param name - Name to validate
 * @returns true if preset exists
 *
 * @example
 * ```typescript
 * isValidPreset('strict');   // true
 * isValidPreset('custom');   // false
 * ```
 */
export function isValidPreset(name: string): boolean {
  return name in PRESETS;
}

/**
 * Get all preset names
 *
 * @returns Array of preset names
 *
 * @example
 * ```typescript
 * getPresetNames();
 * // ['strict', 'balanced', 'lenient', 'ui']
 * ```
 */
export function getPresetNames(): string[] {
  return Object.keys(PRESETS);
}

/**
 * Create a custom preset by extending an existing one
 *
 * Useful for creating variations of built-in presets.
 *
 * @param baseName - Name of preset to extend ('strict' | 'balanced' | 'lenient' | 'ui')
 * @param overrides - Options to override
 * @returns New preset configuration
 *
 * @example
 * ```typescript
 * // Create a "super strict" preset
 * const superStrict = extendPreset('strict', {
 *   name: 'super-strict',
 *   fixedLength: 16,
 *   showTail: 2,
 *   validators: {
 *     minLength: 32,
 *     noSpaces: true,
 *     requirePrefix: true,
 *   }
 * });
 *
 * // Create a UI preset with custom mask character
 * const customUI = extendPreset('ui', {
 *   name: 'custom-ui',
 *   maskChar: '─',
 * });
 * ```
 */
export function extendPreset(
  baseName: keyof typeof PRESETS,
  overrides: Partial<PresetConfig>,
): PresetConfig {
  const base = PRESETS[baseName];

  if (!base) {
    throw new Error(`Unknown preset: ${baseName}`);
  }

  return {
    ...base,
    ...overrides,
    validators: overrides.validators
      ? { ...base.validators, ...overrides.validators }
      : base.validators,
  };
}

/**
 * Compare two presets
 *
 * Useful for documentation or UI to show differences between presets.
 *
 * @param preset1 - First preset name
 * @param preset2 - Second preset name
 * @returns Object showing differences
 *
 * @example
 * ```typescript
 * comparePresets('strict', 'lenient');
 * // {
 * //   fixedLength: { strict: 12, lenient: 6 },
 * //   showHead: { strict: 0, lenient: 4 },
 * //   showTail: { strict: 4, lenient: 6 },
 * //   maskChar: { strict: '•', lenient: '*' },
 * //   warnIfPlain: { strict: true, lenient: false }
 * // }
 * ```
 */
export function comparePresets(
  preset1: keyof typeof PRESETS,
  preset2: keyof typeof PRESETS,
): Record<string, { [key: string]: unknown }> {
  const config1 = PRESETS[preset1];
  const config2 = PRESETS[preset2];

  if (!config1 || !config2) {
    throw new Error("Invalid preset names");
  }

  const differences: Record<string, { [key: string]: unknown }> = {};

  // Compare each option
  const keys = new Set([...Object.keys(config1), ...Object.keys(config2)]);

  for (const key of keys) {
    const val1 = config1[key as keyof PresetConfig];
    const val2 = config2[key as keyof PresetConfig];

    if (JSON.stringify(val1) !== JSON.stringify(val2)) {
      differences[key] = {
        [preset1]: val1,
        [preset2]: val2,
      };
    }
  }

  return differences;
}

/**
 * Get preset recommendation based on use case
 *
 * Helps users choose the right preset for their needs.
 *
 * @param useCase - Description of use case
 * @returns Recommended preset name
 *
 * @example
 * ```typescript
 * recommendPreset('production logs');
 * // 'strict'
 *
 * recommendPreset('settings page');
 * // 'ui'
 *
 * recommendPreset('debugging');
 * // 'lenient'
 * ```
 */
export function recommendPreset(useCase: string): keyof typeof PRESETS {
  const lowerCase = useCase.toLowerCase();

  // Production/compliance use cases → strict
  if (
    lowerCase.includes("production") ||
    lowerCase.includes("compliance") ||
    lowerCase.includes("audit") ||
    lowerCase.includes("log") ||
    lowerCase.includes("security")
  ) {
    return "strict";
  }

  // Development/debugging use cases → lenient
  if (
    lowerCase.includes("debug") ||
    lowerCase.includes("development") ||
    lowerCase.includes("local") ||
    lowerCase.includes("test")
  ) {
    return "lenient";
  }

  // UI use cases → ui
  if (
    lowerCase.includes("ui") ||
    lowerCase.includes("interface") ||
    lowerCase.includes("dashboard") ||
    lowerCase.includes("settings") ||
    lowerCase.includes("page")
  ) {
    return "ui";
  }

  // Default → balanced
  return "balanced";
}
