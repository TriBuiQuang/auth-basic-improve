import { describe, it, expect } from "@jest/globals";
import { parse } from "../../src/basicAuth";

describe("parse(string)", function () {
   describe("with non string", function () {
      it("should throw", function () {
         // @ts-expect-error - testing that non-string throws
         expect(() => parse(undefined)).toThrow(/Expected a string/);
      });
   });

   describe("with malformed string", function () {
      it("should return undefined", function () {
         expect(parse("Something")).toBeUndefined();
      });
   });

   describe("with malformed scheme", function () {
      it("should return undefined", function () {
         expect(parse("basic_Zm9vOmJhcg==")).toBeUndefined();
      });
   });

   describe("with malformed credentials", function () {
      it("should return undefined", function () {
         expect(parse("basic Zm9vcgo=")).toBeUndefined();
      });
   });

   describe("with valid credentials", function () {
      it("should return .name and .pass", function () {
         const creds = parse("basic Zm9vOmJhcg==");
         expect(creds?.name).toBe("foo");
         expect(creds?.pass).toBe("bar");
      });
   });

   describe("with empty password", function () {
      it("should return .name and .pass", function () {
         const creds = parse("basic Zm9vOg==");
         expect(creds?.name).toBe("foo");
         expect(creds?.pass).toBe("");
      });
   });

   describe("with empty userid", function () {
      it("should return .name and .pass", function () {
         const creds = parse("basic OnBhc3M=");
         expect(creds?.name).toBe("");
         expect(creds?.pass).toBe("pass");
      });
   });

   describe("with empty userid and pass", function () {
      it("should return .name and .pass", function () {
         const creds = parse("basic Og==");
         expect(creds?.name).toBe("");
         expect(creds?.pass).toBe("");
      });
   });

   describe("with colon in pass", function () {
      it("should return .name and .pass", function () {
         const creds = parse("basic Zm9vOnBhc3M6d29yZA==");
         expect(creds?.name).toBe("foo");
         expect(creds?.pass).toBe("pass:word");
      });
   });

   describe('with scheme "Basic"', function () {
      it("should return .name and .pass", function () {
         const creds = parse("Basic Zm9vOmJhcg==");
         expect(creds?.name).toBe("foo");
         expect(creds?.pass).toBe("bar");
      });
   });

   describe('with scheme "BASIC"', function () {
      it("should return .name and .pass", function () {
         const creds = parse("BASIC Zm9vOmJhcg==");
         expect(creds?.name).toBe("foo");
         expect(creds?.pass).toBe("bar");
      });
   });

   describe('with scheme "BaSiC"', function () {
      it("should return .name and .pass", function () {
         const creds = parse("BaSiC Zm9vOmJhcg==");
         expect(creds?.name).toBe("foo");
         expect(creds?.pass).toBe("bar");
      });
   });
});
