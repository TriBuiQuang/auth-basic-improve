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
});
