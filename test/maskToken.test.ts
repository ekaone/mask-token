// index.test.ts

import { describe, it, expect } from "vitest";
import { maskToken } from "../src/index";

describe("maskToken", () => {
  it("masks using defaults and preserves known prefix", () => {
    const input = "npm_a1b2c3d4e5f6g7h8i9j0";
    expect(maskToken(input)).toBe("npm_••••••••i9j0");
  });

  it("can disable prefix preservation", () => {
    const input = "npm_a1b2c3d4e5f6g7h8i9j0";
    expect(maskToken(input, { preservePrefix: false })).toBe("••••••••i9j0");
  });

  it("supports strict preset", () => {
    const input = "sk_test_1234567890abcdefghijklmn";
    expect(maskToken(input, { preset: "strict" })).toBe(
      "sk_test_••••••••••••klmn",
    );
  });

  it("supports balanced preset", () => {
    const input = "sk_test_1234567890abcdefghijklmn";
    expect(maskToken(input, { preset: "balanced" })).toBe(
      "sk_test_12••••••••klmn",
    );
  });

  it("supports lenient preset", () => {
    const input = "npm_a1b2c3d4e5f6g7h8i9j0";
    expect(maskToken(input, { preset: "lenient" })).toBe(
      "npm_a1b2******h8i9j0",
    );
  });

  it("supports ui preset", () => {
    const input = "npm_a1b2c3d4e5f6g7h8i9j0";
    expect(maskToken(input, { preset: "ui" })).toBe("npm_a1b2••••••••i9j0");
  });

  it("can return metadata when includeMetadata is true", () => {
    const input = "npm_a1b2c3d4e5f6g7h8i9j0";
    const result = maskToken(input, { includeMetadata: true });

    expect(result.masked).toBe("npm_••••••••i9j0");
    expect(result.metadata.prefix).toBe("npm_");
    expect(result.metadata.type).toBe("NPM Token");
    expect(result.original.length).toBe(input.length);
    expect(result.original.hasPrefix).toBe(true);
  });

  it("supports variable-length masking when fixedLength is false", () => {
    const input = "secret123456";
    expect(
      maskToken(input, {
        fixedLength: false,
        showHead: 0,
        showTail: 4,
        maskChar: "*",
        preservePrefix: false,
      }),
    ).toBe("********3456");
  });

  it("supports jwt mode", () => {
    const input = "eyJhbGciOi.eyJzdWIiOi.SflKxwRJ";
    expect(maskToken(input, { mode: "jwt" })).toBe("eyJ•••.eyJ•••.Sfl•••");
  });

  it("calls onWarning when warnIfPlain is enabled and input is suspicious", () => {
    const onWarning = (result: unknown) => {
      expect(result).toBeTruthy();
    };

    const masked = maskToken("undefined", {
      warnIfPlain: true,
      onWarning,
      preservePrefix: false,
    });

    expect(masked).toBe("••••••••ined");
  });

  it("throws on unknown preset", () => {
    expect(() => maskToken("token123", { preset: "nope" as never })).toThrow(
      "Unknown preset",
    );
  });
});
