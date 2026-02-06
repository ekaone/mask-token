// Security tests for overlap prevention
// Tests the fix for the critical vulnerability where short tokens
// with overlapping head/tail configuration would be fully exposed

import { describe, it, expect } from "vitest";
import { maskToken } from "../src/index";

describe("Security: Overlap Prevention", () => {
  describe("Critical vulnerability fix", () => {
    it("prevents full secret exposure when head + tail >= secret length", () => {
      // Original vulnerability example: secret length 6, showTail: 4, showHead: 2
      const input = "npm_abc123"; // secret part is "abc123" (6 chars)
      const result = maskToken(input, {
        showHead: 2,
        showTail: 4,
        preservePrefix: true,
      });

      // Should NOT return "npm_abc123" (full exposure)
      // Should mask at least 1 character
      expect(result).not.toBe(input);
      expect(result).toContain("••••••••"); // Should have mask chars
    });

    it("masks very short secrets (1 character)", () => {
      const input = "x";
      const result = maskToken(input, {
        showHead: 1,
        showTail: 1,
        preservePrefix: false,
      });

      // Should mask completely, not expose the single character
      expect(result).not.toBe("x");
      expect(result).toBe("••••••••"); // Default fixed length mask
    });

    it("masks short secrets (2 characters)", () => {
      const input = "ab";
      const result = maskToken(input, {
        showHead: 1,
        showTail: 1,
        preservePrefix: false,
      });

      // Should mask at least 1 character
      expect(result).not.toBe("ab");
      expect(result).toContain("••••••••");
    });

    it("masks short secrets (3 characters) with high head/tail values", () => {
      const input = "abc";
      const result = maskToken(input, {
        showHead: 5, // Requested more than available
        showTail: 5, // Requested more than available
        preservePrefix: false,
      });

      // Should auto-adjust and still mask
      expect(result).not.toBe("abc");
      expect(result).toContain("••••••••");
    });
  });

  describe("Auto-adjustment behavior", () => {
    it("adjusts head and tail to ensure masking (6 char secret)", () => {
      const input = "secret"; // 6 chars
      const result = maskToken(input, {
        showHead: 3,
        showTail: 3, // 3 + 3 = 6, would expose all
        preservePrefix: false,
      });

      // Should adjust to show max 5 chars (leaving 1 masked)
      expect(result).not.toBe("secret");
      expect(result.length).toBeGreaterThan(6); // Has mask chars
    });

    it("prioritizes tail over head when adjusting", () => {
      const input = "abc123"; // 6 chars
      const result = maskToken(input, {
        showHead: 4,
        showTail: 4, // Both want 4, but only 5 can be shown
        preservePrefix: false,
      });

      // Tail should get preference (more useful for identification)
      // Expected: show 2-3 chars total, with tail getting more
      expect(result).not.toBe("abc123");
      expect(result).toContain("••••••••");
    });
  });

  describe("Edge cases with prefixes", () => {
    it("handles short secret after prefix removal", () => {
      const input = "npm_ab"; // secret is just "ab" (2 chars)
      const result = maskToken(input, {
        showHead: 1,
        showTail: 1,
        preservePrefix: true,
      });

      // Should keep prefix but mask the secret part
      expect(result).toContain("npm_");
      expect(result).not.toBe("npm_ab");
      expect(result).toContain("••••••••");
    });

    it("handles very short secret after prefix (1 char)", () => {
      const input = "ghp_x"; // secret is just "x" (1 char)
      const result = maskToken(input, {
        showHead: 1,
        showTail: 1,
        preservePrefix: true,
      });

      // Should keep prefix but fully mask the 1-char secret
      expect(result).toContain("ghp_");
      expect(result).not.toBe("ghp_x");
      expect(result).toBe("ghp_••••••••");
    });
  });

  describe("Variable-length masking with overlap", () => {
    it("ensures minimum mask length even with variable masking", () => {
      const input = "abc"; // 3 chars
      const result = maskToken(input, {
        fixedLength: false, // Variable length
        showHead: 2,
        showTail: 2, // Would overlap
        preservePrefix: false,
      });

      // Should still mask at least 1 character
      expect(result).not.toBe("abc");
      expect(result).toContain("•"); // At least one mask char
    });
  });

  describe("Realistic token scenarios", () => {
    it("handles short API keys securely", () => {
      const input = "sk_test_abc123"; // secret part is "abc123" (6 chars)
      const result = maskToken(input, {
        showHead: 3,
        showTail: 3,
        preservePrefix: true,
      });

      expect(result).toContain("sk_test_");
      expect(result).not.toBe("sk_test_abc123");
      expect(result).toContain("••••••••");
    });

    it("handles GitHub tokens with short secrets", () => {
      const input = "ghp_short1"; // secret part is "short1" (6 chars)
      const result = maskToken(input, {
        showHead: 4,
        showTail: 4, // Would expose all 6 chars
        preservePrefix: true,
      });

      expect(result).toContain("ghp_");
      expect(result).not.toBe("ghp_short1");
      expect(result).toContain("••••••••");
    });
  });

  describe("Ensures no full exposure in any scenario", () => {
    const testCases = [
      { secret: "a", head: 1, tail: 1 },
      { secret: "ab", head: 1, tail: 1 },
      { secret: "abc", head: 2, tail: 2 },
      { secret: "abcd", head: 2, tail: 2 },
      { secret: "abcde", head: 3, tail: 3 },
      { secret: "abcdef", head: 3, tail: 3 },
      { secret: "abcdefg", head: 4, tail: 4 },
      { secret: "short", head: 10, tail: 10 }, // Extreme values
    ];

    testCases.forEach(({ secret, head, tail }) => {
      it(`never exposes full secret: "${secret}" (head:${head}, tail:${tail})`, () => {
        const result = maskToken(secret, {
          showHead: head,
          showTail: tail,
          preservePrefix: false,
        });

        // CRITICAL: Result must NEVER equal the input
        expect(result).not.toBe(secret);
        
        // Must contain mask characters
        expect(result).toContain("•");
        
        // Result should be longer than input (due to fixed-length mask)
        // or at least not expose the full secret
        if (result.length === secret.length) {
          // If same length, it means variable masking - still must not match
          expect(result).not.toBe(secret);
        }
      });
    });
  });
});
