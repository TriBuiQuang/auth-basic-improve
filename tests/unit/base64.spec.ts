import { describe, it, expect } from "@jest/globals";
import { base64 } from "../../src/basicAuth/base64";

describe("base64", () => {
   describe("Buffer", () => {
      it("should encode base64", () => {
         expect(base64.encode("foo:bar")).toBe("Zm9vOmJhcg==");
      });

      it("should decode base64", () => {
         expect(base64.decode("Zm9vOmJhcg==")).toBe("foo:bar");
      });
   });

   describe("Unicode / UTF-8", () => {
      it("should encode and decode UTF-8 strings with accented characters", () => {
         const input = "jürgen:pässwörd";
         const encoded = base64.encode(input);
         expect(base64.decode(encoded)).toBe(input);
      });

      it("should encode and decode Japanese characters", () => {
         const input = "日本語:パスワード";
         const encoded = base64.encode(input);
         expect(base64.decode(encoded)).toBe(input);
      });

      it("should encode and decode emoji", () => {
         const input = "🔐:🔑";
         const encoded = base64.encode(input);
         expect(base64.decode(encoded)).toBe(input);
      });

      it("should encode and decode mixed Unicode", () => {
         const input = "用户:密码_日本語🎉";
         const encoded = base64.encode(input);
         expect(base64.decode(encoded)).toBe(input);
      });
   });

   describe("Edge cases", () => {
      it("should handle empty string", () => {
         expect(base64.encode("")).toBe("");
         expect(base64.decode("")).toBe("");
      });

      it("should handle strings with null bytes", () => {
         const input = "abc\0def";
         const encoded = base64.encode(input);
         expect(base64.decode(encoded)).toBe(input);
      });

      it("should handle strings with control characters", () => {
         const input = "test\x00\x01\x1Fdata";
         const encoded = base64.encode(input);
         expect(base64.decode(encoded)).toBe(input);
      });

      it("should handle binary data (bytes 0-255)", () => {
         const bytes = Array.from({ length: 256 }, (_, i) => String.fromCharCode(i));
         const binary = bytes.join("");
         const encoded = base64.encode(binary);
         expect(base64.decode(encoded)).toBe(binary);
      });

      it("should handle long strings", () => {
         const long = "a".repeat(10000) + ":password";
         const encoded = base64.encode(long);
         expect(base64.decode(encoded)).toBe(long);
      });

      it("should handle special characters", () => {
         const input = "user@domain.com:p@ss!w0rd#$%^&*()";
         const encoded = base64.encode(input);
         expect(base64.decode(encoded)).toBe(input);
      });
   });
});
