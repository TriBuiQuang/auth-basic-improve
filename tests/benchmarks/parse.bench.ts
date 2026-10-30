import { describe, it } from "@jest/globals";
import { parse } from "../../src/basicAuth";

describe("parse benchmarks", () => {
   it("basic auth header", () => {
      const header = "Basic dGVzdDpwYXNzd29yZA=="; // "test:password" in base64
      parse(header);
   });

   it("basic auth header with extra whitespace", () => {
      const header = "   Basic   dGVzdDpwYXNzd29yZA==   "; // "test:password" in base64 with extra whitespace
      parse(header);
   });

   it("invalid basic auth header", () => {
      const header = "Basic invalidbase64"; // Invalid base64 string
      parse(header);
   });

   it("non-basic auth header", () => {
      const header = "Bearer sometoken"; // Not a basic auth header
      parse(header);
   });
});
