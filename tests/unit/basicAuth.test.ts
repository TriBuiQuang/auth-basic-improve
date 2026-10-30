import { Request } from "express";

import { auth, parse, Credentials } from "../../src/basicAuth";

const request = (authorization?: string) => {
   return { headers: { authorization } };
};

const assertCreds = (creds: Credentials | undefined): Credentials => {
   if (creds === undefined) throw new Error("Expected Credentials, got undefined");
   return creds;
};

describe("auth(req as Request)", () => {
   describe("arguments", () => {
      describe("req", () => {
         it("should be required", () => {
            expect(() => (auth as unknown as () => void)()).toThrow(/argument req is required/);
         });

         it("should accept a request", () => {
            const req = request("basic Zm9vOmJhcg==");
            const creds = assertCreds(auth(req as Request));
            expect(creds.name).toStrictEqual("foo");
            expect(creds.pass).toStrictEqual("bar");
         });
      });
   });

   describe("with no Authorization field", () => {
      it("should return undefined", () => {
         const req = request();
         expect(auth(req as Request)).toStrictEqual(undefined);
      });
   });

   describe("with malformed Authorization field", () => {
      it("should return undefined", () => {
         const req = request("Something");
         expect(auth(req as Request)).toStrictEqual(undefined);
      });
   });

   describe("with malformed Authorization scheme", () => {
      it("should return undefined", () => {
         const req = request("basic_Zm9vOmJhcg==");
         expect(auth(req as Request)).toStrictEqual(undefined);
      });
   });

   describe("with malformed credentials", () => {
      it("should return undefined", () => {
         const req = request("basic Zm9vcgo=");
         expect(auth(req as Request)).toStrictEqual(undefined);
      });
   });

   describe("with valid credentials", () => {
      it("should return .name and .pass", () => {
         const req = request("basic Zm9vOmJhcg==");
         const creds = assertCreds(auth(req as Request));
         expect(creds.name).toStrictEqual("foo");
         expect(creds.pass).toStrictEqual("bar");
      });
   });

   describe("with empty password", () => {
      it("should return .name and .pass", () => {
         const req = request("basic Zm9vOg==");
         const creds = assertCreds(auth(req as Request));

         expect(creds.name).toStrictEqual("foo");
         expect(creds.pass).toStrictEqual("");
      });
   });

   describe("with empty userid", () => {
      it("should return .name and .pass", () => {
         const req = request("basic OnBhc3M=");
         const creds = assertCreds(auth(req as Request));
         expect(creds.name).toStrictEqual("");
         expect(creds.pass).toStrictEqual("pass");
      });
   });

   describe("with empty userid and pass", () => {
      it("should return .name and .pass", () => {
         const req = request("basic Og==");
         const creds = assertCreds(auth(req as Request));
         expect(creds.name).toStrictEqual("");
         expect(creds.pass).toStrictEqual("");
      });
   });

   describe("with colon in pass", () => {
      it("should return .name and .pass", () => {
         const req = request("basic Zm9vOnBhc3M6d29yZA==");
         const creds = assertCreds(auth(req as Request));
         expect(creds.name).toStrictEqual("foo");
         expect(creds.pass).toStrictEqual("pass:word");
      });
   });
});

describe("parse(string)", () => {
   describe("with non-string input", () => {
      it("should throw a TypeError for null", () => {
         expect(() => parse(null as unknown as string)).toThrow(new TypeError("Expected a string"));
      });

      it("should throw a TypeError for undefined", () => {
         expect(() => parse(undefined as unknown as string)).toThrow(
            new TypeError("Expected a string"),
         );
      });

      it("should throw a TypeError for a number", () => {
         expect(() => parse(42 as unknown as string)).toThrow(new TypeError("Expected a string"));
      });

      it("should throw a TypeError for an object", () => {
         expect(() => parse({} as unknown as string)).toThrow(new TypeError("Expected a string"));
      });
   });

   describe("with malformed string", () => {
      it("should return undefined", () => {
         expect(parse("something")).toStrictEqual(undefined);
      });
   });

   describe("with malformed scheme", () => {
      it("should return undefined", () => {
         expect(parse("basic_Zm9vOmJhcg==")).toStrictEqual(undefined);
      });
   });

   describe("with malformed credentials", () => {
      it("should return undefined", () => {
         expect(parse("basic Zm9vcgo=")).toStrictEqual(undefined);
      });
   });

   describe("with valid credentials", () => {
      it("should return .name and .pass", () => {
         const creds = assertCreds(parse("basic Zm9vOmJhcg=="));
         expect(creds.name).toStrictEqual("foo");
         expect(creds.pass).toStrictEqual("bar");
      });
   });

   describe("with empty password", () => {
      it("should return .name and .pass", () => {
         const creds = assertCreds(parse("basic Zm9vOg=="));
         expect(creds.name).toStrictEqual("foo");
         expect(creds.pass).toStrictEqual("");
      });
   });

   describe("with empty userid", () => {
      it("should return .name and .pass", () => {
         const creds = assertCreds(parse("basic OnBhc3M="));
         expect(creds.name).toStrictEqual("");
         expect(creds.pass).toStrictEqual("pass");
      });
   });

   describe("with empty userid and pass", () => {
      it("should return .name and .pass", () => {
         const creds = assertCreds(parse("basic Og=="));
         expect(creds.name).toStrictEqual("");
         expect(creds.pass).toStrictEqual("");
      });
   });

   describe("with colon in pass", () => {
      it("should return .name and .pass", () => {
         const creds = assertCreds(parse("basic Zm9vOnBhc3M6d29yZA=="));
         expect(creds.name).toStrictEqual("foo");
         expect(creds.pass).toStrictEqual("pass:word");
      });
   });
});
