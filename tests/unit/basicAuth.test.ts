import { Request } from "express";

import { auth, parse } from "@/basicAuth";

const request = (authorization?: string) => {
   return { headers: { authorization } };
};

describe("auth(req as Request)", () => {
   describe("arguments", () => {
      describe("req", () => {
         it("should be required", () => {
            expect(auth).toThrowError(/argument req is required/);
         });

         it("should accept a request", () => {
            const req = request("basic Zm9vOmJhcg==");
            const creds = auth(req as Request);
            expect(creds.name).toStrictEqual("foo");
            expect(creds.pass).toStrictEqual("bar");
         });
      });
   });

   describe("with no Authorization field", () => {
      it("should return empty", () => {
         const req = request();
         expect(auth(req as Request)).toStrictEqual("");
      });
   });

   describe("with malformed Authorization field", () => {
      it("should return empty", () => {
         const req = request("Something");
         expect(auth(req as Request)).toStrictEqual("");
      });
   });

   describe("with malformed Authorization scheme", () => {
      it("should return empty", () => {
         const req = request("basic_Zm9vOmJhcg==");
         expect(auth(req as Request)).toStrictEqual("");
      });
   });

   describe("with malformed credentials", () => {
      it("should return empty", () => {
         const req = request("basic Zm9vcgo=");
         expect(auth(req as Request)).toStrictEqual("");
      });
   });

   describe("with valid credentials", () => {
      it("should return .name and .pass", () => {
         const req = request("basic Zm9vOmJhcg==");
         const creds = auth(req as Request);
         expect(creds.name).toStrictEqual("foo");
         expect(creds.pass).toStrictEqual("bar");
      });
   });

   describe("with empty password", () => {
      it("should return .name and .pass", () => {
         const req = request("basic Zm9vOg==");
         const creds = auth(req as Request);

         expect(creds.name).toStrictEqual("foo");
         expect(creds.pass).toStrictEqual("");
      });
   });

   describe("with empty userid", () => {
      it("should return .name and .pass", () => {
         const req = request("basic OnBhc3M=");
         const creds = auth(req as Request);
         expect(creds.name).toStrictEqual("");
         expect(creds.pass).toStrictEqual("pass");
      });
   });

   describe("with empty userid and pass", () => {
      it("should return .name and .pass", () => {
         const req = request("basic Og==");
         const creds = auth(req as Request);
         expect(creds.name).toStrictEqual("");
         expect(creds.pass).toStrictEqual("");
      });
   });

   describe("with colon in pass", () => {
      it("should return .name and .pass", () => {
         const req = request("basic Zm9vOnBhc3M6d29yZA==");
         const creds = auth(req as Request);
         expect(creds.name).toStrictEqual("foo");
         expect(creds.pass).toStrictEqual("pass:word");
      });
   });
});

describe("parse(string)", () => {
   describe("with undefined string", () => {
      it("should return empty", () => {
         expect(parse()).toStrictEqual("");
      });
   });

   describe("with malformed string", () => {
      it("should return empty", () => {
         expect(parse("something")).toStrictEqual("");
      });
   });

   describe("with malformed scheme", () => {
      it("should return empty", () => {
         expect(parse("basic_Zm9vOmJhcg==")).toStrictEqual("");
      });
   });

   describe("with malformed credentials", () => {
      it("should return empty", () => {
         expect(parse("basic Zm9vcgo=")).toStrictEqual("");
      });
   });

   describe("with valid credentials", () => {
      it("should return .name and .pass", () => {
         const creds = parse("basic Zm9vOmJhcg==");
         expect(creds.name).toStrictEqual("foo");
         expect(creds.pass).toStrictEqual("bar");
      });
   });

   describe("with empty password", () => {
      it("should return .name and .pass", () => {
         const creds = parse("basic Zm9vOg==");
         expect(creds.name).toStrictEqual("foo");
         expect(creds.pass).toStrictEqual("");
      });
   });

   describe("with empty userid", () => {
      it("should return .name and .pass", () => {
         const creds = parse("basic OnBhc3M=");
         expect(creds.name).toStrictEqual("");
         expect(creds.pass).toStrictEqual("pass");
      });
   });

   describe("with empty userid and pass", () => {
      it("should return .name and .pass", () => {
         const creds = parse("basic Og==");
         expect(creds.name).toStrictEqual("");
         expect(creds.pass).toStrictEqual("");
      });
   });

   describe("with colon in pass", () => {
      it("should return .name and .pass", () => {
         const creds = parse("basic Zm9vOnBhc3M6d29yZA==");
         expect(creds.name).toStrictEqual("foo");
         expect(creds.pass).toStrictEqual("pass:word");
      });
   });
});
