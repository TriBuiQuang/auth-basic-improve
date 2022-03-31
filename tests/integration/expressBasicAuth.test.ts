import express, { Request, Response } from "express";
import supertest from "supertest";

import basicAuth from "@/expressBasicAuth";
import { IBasicAuthedRequest } from "@/interfaces/expressBasicAuth.interface";

const app = express();

// Custom authorizer checking if the username starts with 'A' and the password with 'secret'
const myAuthorizer = (username: string, password: string) => {
   return username.startsWith("A") && password.startsWith("secret");
};

// Requires basic auth with username 'Admin' and password 'secret1234'
const staticUserAuth = basicAuth({
   challenge: false,
   users: { Admin: "secret1234" },
});

// Uses a custom (synchronous) authorizer function
const customAuthorizerAuth = basicAuth({ authorizer: myAuthorizer });

// Same but asynchronous
const myAsyncAuthorizer = (username: string, password: string, cb: any) => {
   if (username.startsWith("A") && password.startsWith("secret")) return cb(null, true);
   return cb(null, false);
};

const myComparingAuthorizer = (username: string, password: string) => {
   return (
      basicAuth.safeCompare(username, "Testeroni") && basicAuth.safeCompare(password, "testsecret")
   );
};

function getUnauthorizedResponse(req: IBasicAuthedRequest) {
   return req.auth
      ? `Credentials ${req.auth.user}:${req.auth.password} rejected`
      : "No credentials provided";
}

// Uses a custom (synchronous) authorizer function
const customCompareAuth = basicAuth({
   authorizer: myComparingAuthorizer,
});

// Same, but sends a basic auth challenge header when authorization fails
const challengeAuth = basicAuth({
   authorizer: myAuthorizer,
   challenge: true,
});

// Uses a custom asynchronous authorizer function
const asyncAuth = basicAuth({
   authorizeAsync: true,
   authorizer: myAsyncAuthorizer,
});

// Uses a custom response body function
const customBodyAuth = basicAuth({
   unauthorizedResponse: getUnauthorizedResponse,
   users: { Foo: "bar" },
});

// Uses a static response body
const staticBodyAuth = basicAuth({
   unauthorizedResponse: "Haaaaaha",
});

// Uses a JSON response body
const jsonBodyAuth = basicAuth({
   unauthorizedResponse: { foo: "bar" },
});

// Uses a custom realm
const realmAuth = basicAuth({
   challenge: true,
   realm: "test",
});

// Uses a custom realm function
const realmFunctionAuth = basicAuth({
   challenge: true,
   realm() {
      return "bla";
   },
});

app.get("/static", staticUserAuth, (req: Request, res: Response) => {
   res.status(200).send("You passed");
});

app.get("/custom", customAuthorizerAuth, (req: Request, res: Response) => {
   res.status(200).send("You passed");
});

app.get("/custom-compare", customCompareAuth, (req: Request, res: Response) => {
   res.status(200).send("You passed");
});

app.get("/challenge", challengeAuth, (req: Request, res: Response) => {
   res.status(200).send("You passed");
});

app.get("/async", asyncAuth, (req: Request, res: Response) => {
   res.status(200).send("You passed");
});

app.get("/custombody", customBodyAuth, (req: Request, res: Response) => {
   res.status(200).send("You passed");
});

app.get("/staticbody", staticBodyAuth, (req: Request, res: Response) => {
   res.status(200).send("You passed");
});

app.get("/jsonbody", jsonBodyAuth, (req: Request, res: Response) => {
   res.status(200).send("You passed");
});

app.get("/realm", realmAuth, (req: Request, res: Response) => {
   res.status(200).send("You passed");
});

app.get("/realmfunction", realmFunctionAuth, (req: Request, res: Response) => {
   res.status(200).send("You passed");
});

describe("express-basic-auth", () => {
   describe("safe compare", () => {
      const { safeCompare } = basicAuth;

      it("should return false on different inputs", () => {
         expect(!!safeCompare("asdf", "rftghe")).toBe(false);
      });

      it("should return false on prefix inputs", () => {
         expect(!!safeCompare("some", "something")).toBe(false);
      });

      it("should return true on same inputs", () => {
         expect(!!safeCompare("anothersecret", "anothersecret")).toBe(true);
      });
   });

   describe("static users", () => {
      const endpoint = "/static";

      it("should reject on missing header", (done) => {
         supertest(app).get(endpoint).expect(401, done);
      });

      it("should reject on wrong credentials", (done) => {
         supertest(app).get(endpoint).auth("dude", "stuff").expect(401, done);
      });

      it("should reject on shorter prefix", (done) => {
         supertest(app).get(endpoint).auth("Admin", "secret").expect(401, done);
      });

      it("should reject without challenge", (done) => {
         supertest(app)
            .get(endpoint)
            .auth("dude", "stuff")
            .expect((res: any) => {
               if (res.headers["WWW-Authenticate"])
                  throw new Error("Response should not have a challenge");
            })
            .expect(401, done);
      });

      it("should accept correct credentials", (done) => {
         supertest(app).get(endpoint).auth("Admin", "secret1234").expect(200, "You passed", done);
      });
   });

   describe("custom authorizer", () => {
      const endpoint = "/custom";

      it("should reject on missing header", (done) => {
         supertest(app).get(endpoint).expect(401, done);
      });

      it("should reject on wrong credentials", (done) => {
         supertest(app).get(endpoint).auth("dude", "stuff").expect(401, done);
      });

      it("should accept fitting credentials", (done) => {
         supertest(app)
            .get(endpoint)
            .auth("Aloha", "secretverymuch")
            .expect(200, "You passed", done);
      });

      describe("with safe compare", () => {
         const endpoint = "/custom-compare";

         it("should reject wrong credentials", (done) => {
            supertest(app).get(endpoint).auth("bla", "blub").expect(401, done);
         });

         it("should reject prefix credentials", (done) => {
            supertest(app).get(endpoint).auth("Test", "test").expect(401, done);
         });

         it("should accept fitting credentials", (done) => {
            supertest(app)
               .get(endpoint)
               .auth("Testeroni", "testsecret")
               .expect(200, "You passed", done);
         });
      });
   });

   describe("async authorizer", () => {
      const endpoint = "/async";

      it("should reject on missing header", (done) => {
         supertest(app).get(endpoint).expect(401, done);
      });

      it("should reject on wrong credentials", (done) => {
         supertest(app).get(endpoint).auth("dude", "stuff").expect(401, done);
      });

      it("should accept fitting credentials", (done) => {
         supertest(app)
            .get(endpoint)
            .auth("Aererer", "secretiveStuff")
            .expect(200, "You passed", done);
      });
   });

   describe("custom response body", () => {
      it("should reject on missing header and generate resposne message", (done) => {
         supertest(app).get("/custombody").expect(401, "No credentials provided", done);
      });

      it("should reject on wrong credentials and generate response message", (done) => {
         supertest(app)
            .get("/custombody")
            .auth("dude", "stuff")
            .expect(401, "Credentials dude:stuff rejected", done);
      });

      it("should accept fitting credentials", (done) => {
         supertest(app).get("/custombody").auth("Foo", "bar").expect(200, "You passed", done);
      });

      it("should reject and send static custom resposne message", (done) => {
         supertest(app).get("/staticbody").expect(401, "Haaaaaha", done);
      });

      it("should reject and send static custom json resposne message", (done) => {
         supertest(app).get("/jsonbody").expect(401, { foo: "bar" }, done);
      });
   });

   describe("challenge", () => {
      it("should reject with blank challenge", (done) => {
         supertest(app).get("/challenge").expect("WWW-Authenticate", "Basic").expect(401, done);
      });

      it("should reject with custom realm challenge", (done) => {
         supertest(app)
            .get("/realm")
            .expect("WWW-Authenticate", 'Basic realm="test"')
            .expect(401, done);
      });

      it("should reject with custom generated realm challenge", (done) => {
         supertest(app)
            .get("/realmfunction")
            .expect("WWW-Authenticate", 'Basic realm="bla"')
            .expect(401, done);
      });
   });
});
