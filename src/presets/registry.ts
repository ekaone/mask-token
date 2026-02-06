/**
 * mask-token - Secure token masking with NIST/PCI-DSS/OWASP compliance
 *
 * Known token prefix registry and detection logic
 *
 * Feature #1: Automated Known-Prefix Preservation
 *
 * @module presets/registry
 */

import type { TokenMetadata, PrefixDefinition } from "../types";
import { MIN_TOKEN_LENGTH, MIN_ENTROPY_RATIO } from "../utils/constants";

// ============================================================================
// KNOWN PREFIX DEFINITIONS
// ============================================================================

/**
 * Registry of known token prefixes
 *
 * This is the core of Feature #1 (Automated Known-Prefix Preservation).
 * Each entry defines a token format that should be automatically detected.
 *
 * Organized by service/platform for maintainability.
 */
export const KNOWN_PREFIXES: readonly PrefixDefinition[] = [
  // ==========================================================================
  // NPM (Node Package Manager)
  // ==========================================================================
  {
    pattern: "npm_",
    name: "NPM Token",
    minLength: 36,
    category: "api",
  },

  // ==========================================================================
  // GitHub
  // ==========================================================================
  {
    pattern: "ghp_",
    name: "GitHub Personal Access Token",
    minLength: 40,
    category: "oauth",
  },
  {
    pattern: "gho_",
    name: "GitHub OAuth Access Token",
    minLength: 40,
    category: "oauth",
  },
  {
    pattern: "ghu_",
    name: "GitHub User-to-Server Token",
    minLength: 40,
    category: "oauth",
  },
  {
    pattern: "ghs_",
    name: "GitHub Server-to-Server Token",
    minLength: 40,
    category: "api",
  },
  {
    pattern: "ghr_",
    name: "GitHub Refresh Token",
    minLength: 40,
    category: "oauth",
  },

  // ==========================================================================
  // GitLab
  // ==========================================================================
  {
    pattern: "glpat-",
    name: "GitLab Personal Access Token",
    minLength: 20,
    category: "api",
  },
  {
    pattern: "gldt-",
    name: "GitLab Deploy Token",
    minLength: 20,
    category: "api",
  },

  // ==========================================================================
  // Stripe
  // ==========================================================================
  {
    pattern: /^sk_(test|live)_/,
    name: "Stripe Secret Key",
    minLength: 32,
    category: "secret",
  },
  {
    pattern: /^pk_(test|live)_/,
    name: "Stripe Publishable Key",
    minLength: 32,
    category: "key",
  },
  {
    pattern: /^rk_(test|live)_/,
    name: "Stripe Restricted Key",
    minLength: 32,
    category: "key",
  },

  // ==========================================================================
  // Slack
  // ==========================================================================
  {
    pattern: "xoxb-",
    name: "Slack Bot Token",
    minLength: 50,
    category: "oauth",
  },
  {
    pattern: "xoxp-",
    name: "Slack User Token",
    minLength: 50,
    category: "oauth",
  },
  {
    pattern: "xoxa-",
    name: "Slack Access Token",
    minLength: 50,
    category: "oauth",
  },
  {
    pattern: "xoxr-",
    name: "Slack Refresh Token",
    minLength: 50,
    category: "oauth",
  },
  {
    pattern: "xapp-",
    name: "Slack App-Level Token",
    minLength: 50,
    category: "api",
  },

  // ==========================================================================
  // AWS (Amazon Web Services)
  // ==========================================================================
  {
    pattern: "AKIA",
    name: "AWS Access Key ID",
    minLength: 20,
    category: "key",
  },
  {
    pattern: "ASIA",
    name: "AWS Session Token",
    minLength: 20,
    category: "key",
  },

  // ==========================================================================
  // Google Cloud Platform
  // ==========================================================================
  {
    pattern: "AIza",
    name: "Google API Key",
    minLength: 39,
    category: "api",
  },

  // ==========================================================================
  // OpenAI
  // ==========================================================================
  {
    pattern: "sk-",
    name: "OpenAI Secret Key",
    minLength: 48,
    category: "secret",
  },
  {
    pattern: "sk-proj-",
    name: "OpenAI Project Key",
    minLength: 48,
    category: "secret",
  },

  // ==========================================================================
  // Anthropic (Claude)
  // ==========================================================================
  {
    pattern: "sk-ant-",
    name: "Anthropic API Key",
    minLength: 40,
    category: "secret",
  },

  // ==========================================================================
  // Twilio
  // ==========================================================================
  {
    pattern: /^SK[a-f0-9]{32}$/,
    name: "Twilio API Key",
    minLength: 34,
    category: "api",
  },
  {
    pattern: /^AC[a-f0-9]{32}$/,
    name: "Twilio Account SID",
    minLength: 34,
    category: "api",
  },

  // ==========================================================================
  // SendGrid
  // ==========================================================================
  {
    pattern: "SG.",
    name: "SendGrid API Key",
    minLength: 69,
    category: "api",
  },

  // ==========================================================================
  // Heroku
  // ==========================================================================
  {
    pattern: /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/,
    name: "Heroku API Key",
    minLength: 36,
    category: "api",
  },

  // ==========================================================================
  // Shopify
  // ==========================================================================
  {
    pattern: "shpat_",
    name: "Shopify Private App Token",
    minLength: 32,
    category: "api",
  },
  {
    pattern: "shpca_",
    name: "Shopify Custom App Token",
    minLength: 32,
    category: "api",
  },
  {
    pattern: "shpss_",
    name: "Shopify Shared Secret",
    minLength: 32,
    category: "secret",
  },

  // ==========================================================================
  // Vercel
  // ==========================================================================
  {
    pattern: /^vercel_[a-zA-Z0-9_]+$/,
    name: "Vercel Token",
    minLength: 24,
    category: "api",
  },

  // ==========================================================================
  // Netlify
  // ==========================================================================
  {
    pattern: /^nf[a-zA-Z0-9]{40,}$/,
    name: "Netlify Access Token",
    minLength: 42,
    category: "oauth",
  },

  // ==========================================================================
  // DigitalOcean
  // ==========================================================================
  {
    pattern: "dop_v1_",
    name: "DigitalOcean Personal Access Token",
    minLength: 64,
    category: "api",
  },

  // ==========================================================================
  // Docker Hub
  // ==========================================================================
  {
    pattern: "dckr_pat_",
    name: "Docker Hub Personal Access Token",
    minLength: 36,
    category: "api",
  },

  // ==========================================================================
  // Generic Patterns (Lower Confidence)
  // ==========================================================================
  {
    pattern: /^api[_-]?key[_-]/i,
    name: "Generic API Key",
    category: "api",
  },
  {
    pattern: /^token[_-]/i,
    name: "Generic Token",
    category: "api",
  },
  {
    pattern: /^secret[_-]/i,
    name: "Generic Secret",
    category: "secret",
  },
  {
    pattern: /^[a-z]{2,6}_/,
    name: "Generic Prefixed Token",
    category: "api",
  },
] as const;

// ============================================================================
// CUSTOM PREFIX REGISTRY
// ============================================================================

/**
 * Runtime registry for custom prefixes
 *
 * Allows users to register their own token formats via registerPrefix().
 * Checked with higher priority than KNOWN_PREFIXES.
 */
const customPrefixRegistry = new Map<string, string>();

/**
 * Register a custom token prefix
 *
 * Allows applications to register their own token formats for auto-detection.
 * Custom prefixes have higher priority than built-in prefixes.
 *
 * @param prefix - The prefix string to detect (e.g., 'myapp_')
 * @param description - Human-readable name for the token type
 *
 * @example
 * ```typescript
 * registerPrefix('myapp_', 'MyApp API Key');
 *
 * // Now this will be auto-detected
 * maskToken('myapp_secret123');
 * // → 'myapp_••••••••123'
 * ```
 */
export function registerPrefix(prefix: string, description: string): void {
  if (!prefix || typeof prefix !== "string") {
    throw new Error("Prefix must be a non-empty string");
  }
  if (!description || typeof description !== "string") {
    throw new Error("Description must be a non-empty string");
  }

  customPrefixRegistry.set(prefix, description);
}

/**
 * Get all registered custom prefixes
 *
 * @returns Map of prefix → description
 *
 * @internal
 */
export function getCustomPrefixes(): ReadonlyMap<string, string> {
  return customPrefixRegistry;
}

/**
 * Clear all custom prefixes (useful for testing)
 *
 * @internal
 */
export function clearCustomPrefixes(): void {
  customPrefixRegistry.clear();
}

// ============================================================================
// PREFIX DETECTION LOGIC
// ============================================================================

/**
 * Detect token type from input string
 *
 * Checks input against known prefixes and custom prefixes to identify
 * the token type. Returns metadata including confidence score.
 *
 * Priority order:
 * 1. Custom prefixes (highest priority)
 * 2. User-provided customPrefixes option
 * 3. Built-in KNOWN_PREFIXES
 * 4. Heuristic detection (lowest confidence)
 *
 * @param input - Token string to analyze
 * @param customPrefixes - Optional user-provided prefix definitions
 * @returns Token metadata with type, prefix, confidence, and validity
 *
 * @example
 * ```typescript
 * detectPrefix('npm_abc123xyz');
 * // {
 * //   type: 'NPM Token',
 * //   prefix: 'npm_',
 * //   confidence: 1.0,
 * //   isLikelyToken: true
 * // }
 *
 * detectPrefix('unknown123');
 * // {
 * //   type: 'unknown',
 * //   prefix: null,
 * //   confidence: 0,
 * //   isLikelyToken: true  (passed heuristics)
 * // }
 * ```
 */
export function detectPrefix(
  input: string,
  customPrefixes: Record<string, string> = {},
): TokenMetadata {
  // Early return for invalid input
  if (!input || typeof input !== "string") {
    return {
      type: "unknown",
      prefix: null,
      confidence: 0,
      isLikelyToken: false,
    };
  }

  // Priority 1: Check custom prefixes from options
  for (const [prefix, name] of Object.entries(customPrefixes)) {
    if (input.startsWith(prefix)) {
      return {
        type: name,
        prefix,
        confidence: 1.0,
        isLikelyToken: true,
      };
    }
  }

  // Priority 2: Check runtime-registered custom prefixes
  for (const [prefix, name] of customPrefixRegistry.entries()) {
    if (input.startsWith(prefix)) {
      return {
        type: name,
        prefix,
        confidence: 1.0,
        isLikelyToken: true,
      };
    }
  }

  // Priority 3: Check known prefixes
  for (const definition of KNOWN_PREFIXES) {
    const matchResult = matchPrefix(input, definition);

    if (matchResult.matched) {
      // Calculate confidence based on length validation
      let confidence = 0.9;

      if (definition.minLength) {
        if (input.length >= definition.minLength) {
          confidence = 1.0; // Perfect match
        } else if (input.length >= definition.minLength * 0.8) {
          confidence = 0.8; // Close enough
        } else {
          confidence = 0.6; // Too short, but has correct prefix
        }
      }

      return {
        type: definition.name,
        prefix: matchResult.prefix,
        confidence,
        isLikelyToken: confidence > 0.7,
      };
    }
  }

  // Priority 4: No prefix detected - use heuristics
  const isLikelyToken = isLikelyTokenHeuristic(input);

  return {
    type: "unknown",
    prefix: null,
    confidence: 0,
    isLikelyToken,
  };
}

/**
 * Match input against a prefix definition
 *
 * Handles both string and regex patterns.
 *
 * @param input - Token string
 * @param definition - Prefix definition to match against
 * @returns Match result with matched flag and extracted prefix
 *
 * @internal
 */
function matchPrefix(
  input: string,
  definition: PrefixDefinition,
): { matched: boolean; prefix: string | null } {
  const { pattern } = definition;

  // String pattern (simple prefix)
  if (typeof pattern === "string") {
    if (input.startsWith(pattern)) {
      return { matched: true, prefix: pattern };
    }
    return { matched: false, prefix: null };
  }

  // RegExp pattern
  if (pattern instanceof RegExp) {
    const match = input.match(pattern);
    if (match) {
      // Extract the matched prefix (full match or first capture group)
      const prefix = match[0];
      return { matched: true, prefix };
    }
    return { matched: false, prefix: null };
  }

  return { matched: false, prefix: null };
}

/**
 * Heuristic to detect if string looks like a token
 *
 * Uses multiple criteria to determine if an input string has
 * characteristics of a real token, even without a known prefix.
 *
 * Criteria:
 * 1. Length: At least MIN_TOKEN_LENGTH characters (typically 16)
 * 2. No whitespace: Tokens don't contain spaces
 * 3. Valid characters: Only alphanumeric, underscore, hyphen, dot
 * 4. Entropy: At least MIN_ENTROPY_RATIO unique characters (30%)
 *
 * @param input - String to analyze
 * @returns true if input looks like a token
 *
 * @example
 * ```typescript
 * isLikelyTokenHeuristic('abcdefghijklmnop');
 * // → true (16+ chars, no spaces, good entropy)
 *
 * isLikelyTokenHeuristic('hello world');
 * // → false (contains whitespace)
 *
 * isLikelyTokenHeuristic('short');
 * // → false (too short)
 *
 * isLikelyTokenHeuristic('aaaaaaaaaaaaaaaa');
 * // → false (low entropy - only 1 unique char)
 * ```
 */
export function isLikelyTokenHeuristic(input: string): boolean {
  // Check 1: Minimum length
  if (input.length < MIN_TOKEN_LENGTH) {
    return false;
  }

  // Check 2: No whitespace
  if (/\s/.test(input)) {
    return false;
  }

  // Check 3: Valid token characters
  // Allow: letters, numbers, underscore, hyphen, dot, forward slash (for base64)
  if (!/^[A-Za-z0-9_.\-/+=]+$/.test(input)) {
    return false;
  }

  // Check 4: Entropy (character diversity)
  const uniqueChars = new Set(input).size;
  const entropyRatio = uniqueChars / input.length;

  if (entropyRatio < MIN_ENTROPY_RATIO) {
    return false;
  }

  // All checks passed
  return true;
}

/**
 * Get information about a specific prefix
 *
 * Useful for UI or documentation to show what token types are supported.
 *
 * @param prefix - Prefix string to look up
 * @returns Prefix definition or undefined if not found
 *
 * @example
 * ```typescript
 * getPrefixInfo('npm_');
 * // {
 * //   pattern: 'npm_',
 * //   name: 'NPM Token',
 * //   minLength: 36,
 * //   category: 'api'
 * // }
 * ```
 */
export function getPrefixInfo(prefix: string): PrefixDefinition | undefined {
  // Check custom prefixes first
  const customName = customPrefixRegistry.get(prefix);
  if (customName) {
    return {
      pattern: prefix,
      name: customName,
      category: "api",
    };
  }

  // Check known prefixes
  return KNOWN_PREFIXES.find((def) => {
    if (typeof def.pattern === "string") {
      return def.pattern === prefix;
    }
    return false; // Can't easily match regex patterns
  });
}

/**
 * Get all supported prefix patterns
 *
 * Returns a list of all token types that can be auto-detected.
 * Useful for documentation or UI.
 *
 * @returns Array of prefix names
 *
 * @example
 * ```typescript
 * getSupportedPrefixes();
 * // [
 * //   'NPM Token',
 * //   'GitHub Personal Access Token',
 * //   'Stripe Secret Key',
 * //   ...
 * // ]
 * ```
 */
export function getSupportedPrefixes(): string[] {
  const builtIn = KNOWN_PREFIXES.map((def) => def.name);
  const custom = Array.from(customPrefixRegistry.values());

  return [...custom, ...builtIn];
}

/**
 * Get count of registered prefixes
 *
 * @returns Object with counts for each category
 *
 * @example
 * ```typescript
 * getPrefixCount();
 * // {
 * //   total: 45,
 * //   custom: 2,
 * //   builtin: 43,
 * //   byCategory: { api: 25, oauth: 12, secret: 6, key: 2 }
 * // }
 * ```
 */
export function getPrefixCount(): {
  total: number;
  custom: number;
  builtin: number;
  byCategory: Record<string, number>;
} {
  const custom = customPrefixRegistry.size;
  const builtin = KNOWN_PREFIXES.length;

  const byCategory: Record<string, number> = {};
  for (const def of KNOWN_PREFIXES) {
    if (def.category) {
      byCategory[def.category] = (byCategory[def.category] || 0) + 1;
    }
  }

  return {
    total: custom + builtin,
    custom,
    builtin,
    byCategory,
  };
}
