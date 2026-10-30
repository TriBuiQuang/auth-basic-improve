import { describe, it, expect } from "@jest/globals";

import { safeCompare } from "../../src/expressBasicAuth";

describe("safeCompare", () => {
   describe("identical strings", () => {
      it("should return true for matching simple strings", () => {
         expect(safeCompare("hello", "hello")).toBe(true);
      });

      it("should return true for matching empty strings", () => {
         expect(safeCompare("", "")).toBe(true);
      });

      it("should return true for matching long strings", () => {
         const long = "a".repeat(10000);
         expect(safeCompare(long, long)).toBe(true);
      });

      it("should return true for matching Unicode strings", () => {
         expect(safeCompare("jürgen", "jürgen")).toBe(true);
         expect(safeCompare("日本語", "日本語")).toBe(true);
         expect(safeCompare("🔐🔑", "🔐🔑")).toBe(true);
      });

      it("should return true for matching strings with special characters", () => {
         expect(safeCompare("user@domain.com", "user@domain.com")).toBe(true);
         expect(safeCompare("p@ss!w0rd#$%", "p@ss!w0rd#$%")).toBe(true);
      });
   });

   describe("different strings", () => {
      it("should return false for different simple strings", () => {
         expect(safeCompare("hello", "world")).toBe(false);
      });

      it("should return false for strings that share a common prefix", () => {
         expect(safeCompare("Testeroni", "Test")).toBe(false);
         expect(safeCompare("abc", "ab")).toBe(false);
      });

      it("should return false for strings that share a common suffix", () => {
         expect(safeCompare("abc", "xc")).toBe(false);
      });

      it("should return false for strings with different Unicode content", () => {
         expect(safeCompare("jürgen", "jurgen")).toBe(false);
         expect(safeCompare("日本語", "にほんご")).toBe(false);
      });

      it("should return false for strings with different special characters", () => {
         expect(safeCompare("user@domain.com", "user#domain.com")).toBe(false);
      });
   });

   describe("length mismatches", () => {
      it("should return false when strings have different lengths", () => {
         expect(safeCompare("short", "longer")).toBe(false);
         expect(safeCompare("a", "bb")).toBe(false);
         expect(safeCompare("", "x")).toBe(false);
      });

      it("should return false for same ASCII length but different Unicode", () => {
         // "café" and "cafe" have different byte lengths in UTF-8
         expect(safeCompare("café", "cafe")).toBe(false);
      });

      it("should return false for empty vs non-empty", () => {
         expect(safeCompare("", "not empty")).toBe(false);
      });
   });

   describe("edge cases", () => {
      it("should handle null bytes", () => {
         expect(safeCompare("abc\0def", "abc\0def")).toBe(true);
         expect(safeCompare("abc\0def", "abcdef")).toBe(false);
      });

      it("should handle control characters", () => {
         expect(safeCompare("abc\x00def", "abc\x00def")).toBe(true);
         expect(safeCompare("abc\x00def", "abcdef")).toBe(false);
      });

      it("should handle very long strings efficiently", () => {
         const long1 = "x".repeat(100000);
         const long2 = "x".repeat(100000);
         expect(safeCompare(long1, long2)).toBe(true);
      });

      it("should handle binary-like strings", () => {
         const binary = String.fromCharCode(0, 1, 2, 127, 128, 255);
         expect(safeCompare(binary, binary)).toBe(true);
         expect(safeCompare(binary, binary.slice(0, -1))).toBe(false);
      });

      it("should handle Unicode normalization differences (precomposed vs decomposed)", () => {
         // "é" as precomposed U+00E9 vs. decomposed "e" + combining acute U+0301
         const precomposed = "café"; // é = U+00E9
         const decomposed = "cafe\u0301"; // e + combining acute accent
         expect(safeCompare(precomposed, decomposed)).toBe(false);
      });
   });
});
