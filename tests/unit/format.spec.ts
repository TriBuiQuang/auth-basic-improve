import { describe, it, expect } from "@jest/globals";
import { format } from "../../src/basicAuth";

describe("format(credentials)", function () {
   describe("arguments", function () {
      describe("credentials", function () {
         it("should be required", function () {
            // @ts-expect-error - testing that no args throws
            expect(() => format()).toThrow(/Expected an object/);
         });

         it("should accept credentials", function () {
            const header = format({ name: "foo", pass: "bar" });
            expect(header).toBe("Basic Zm9vOmJhcg==");
         });

         it("should reject null", function () {
            // @ts-expect-error - testing that null throws
            expect(() => format(null)).toThrow(/Expected an object/);
         });

         it("should reject a number", function () {
            // @ts-expect-error - testing that number throws
            expect(() => format(42)).toThrow(/Expected an object/);
         });

         it("should reject a string", function () {
            // @ts-expect-error - testing that string throws
            expect(() => format("")).toThrow(/Expected an object/);
         });

         it("should reject an object without name", function () {
            // @ts-expect-error - testing that missing name throws
            expect(() => format({ pass: "bar" })).toThrow(
               /Object must have string properties "name" and "pass"/,
            );
         });

         it("should reject an object without pass", function () {
            // @ts-expect-error - testing that missing pass throws
            expect(() => format({ name: "foo" })).toThrow(
               /Object must have string properties "name" and "pass"/,
            );
         });

         it("should reject an object with non-string name", function () {
            // @ts-expect-error - testing that non-string name throws
            expect(() => format({ name: 42, pass: "bar" })).toThrow(
               /Object must have string properties "name" and "pass"/,
            );
         });

         it("should reject an object with non-string pass", function () {
            // @ts-expect-error - testing that non-string pass throws
            expect(() => format({ name: "foo", pass: 42 })).toThrow(
               /Object must have string properties "name" and "pass"/,
            );
         });

         it("should reject userid containing colon", function () {
            expect(() => format({ name: "foo:bar", pass: "baz" })).toThrow(
               /must not contain a colon/,
            );
         });

         it("should reject control chars in userid", function () {
            expect(() => format({ name: "foo\u0000bar", pass: "baz" })).toThrow(
               /must not contain control characters/,
            );
         });

         it("should reject control chars in password", function () {
            expect(() => format({ name: "foo", pass: "bar\u007f" })).toThrow(
               /must not contain control characters/,
            );
         });
      });
   });

   describe("with valid credentials", function () {
      it("should return header", function () {
         const header = format({ name: "foo", pass: "bar" });
         expect(header).toBe("Basic Zm9vOmJhcg==");
      });
   });

   describe("with empty password", function () {
      it("should return header", function () {
         const header = format({ name: "foo", pass: "" });
         expect(header).toBe("Basic Zm9vOg==");
      });
   });

   describe("with empty userid", function () {
      it("should return header", function () {
         const header = format({ name: "", pass: "pass" });
         expect(header).toBe("Basic OnBhc3M=");
      });
   });

   describe("with empty userid and pass", function () {
      it("should return header", function () {
         const header = format({ name: "", pass: "" });
         expect(header).toBe("Basic Og==");
      });
   });
});
