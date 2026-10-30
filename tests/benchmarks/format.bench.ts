import { describe, it } from "@jest/globals";
import { format } from "../../src/basicAuth";

describe("format benchmarks", () => {
   it("format with simple credentials", () => {
      const credentials = { name: "user", pass: "password" };
      format(credentials);
   });

   it("format with long credentials", () => {
      const credentials = {
         name: "verylongusernameforbasicauth",
         pass: "verylongpasswordwithmanycharactersforbenchmark",
      };
      format(credentials);
   });

   it("format with unicode credentials", () => {
      const credentials = { name: "jürgen", pass: "pässwörd" };
      format(credentials);
   });

   it("format with special characters", () => {
      const credentials = { name: "user@domain", pass: "p@ss!word#123" };
      format(credentials);
   });
});
