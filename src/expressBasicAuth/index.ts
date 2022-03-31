import assert from "assert";
import { timingSafeEqual } from "crypto";

import { Request, Response, NextFunction } from "express";

import { auth } from "@/basicAuth";
import { IBasicAuthedRequest, IbuildMiddleware } from "@/interfaces/expressBasicAuth.interface";
/**
 *
 */
export const safeCompare = (userInput: string, secret: string) => {
   const userInputLength = Buffer.byteLength(userInput);
   const secretLength = Buffer.byteLength(secret);

   const userInputBuffer = Buffer.alloc(userInputLength, 0, "utf8");
   userInputBuffer.write(userInput);
   const secretBuffer = Buffer.alloc(userInputLength, 0, "utf8");
   secretBuffer.write(secret);

   return !!(timingSafeEqual(userInputBuffer, secretBuffer) && userInputLength === secretLength);
};

/**
 * Function check `option` if is function, if undefined return default value, if not a function return it self with function
 */
const ensureFunction = (option?: unknown, defaultValue?: string) => {
   if (option === undefined) return () => defaultValue;

   if (typeof option !== "function") return () => option;

   return option;
};

function buildMiddleware(options: IbuildMiddleware) {
   const challenge = options.challenge !== undefined ? !!options.challenge : false;
   const users = options.users || {};

   const staticUsersAuthorizer = (username: string, password: string) => {
      const keys = Object.keys(users);
      for (let i = 0; i < keys.length; i += 1) {
         const key = keys[i];
         if (safeCompare(username, key) && safeCompare(password, users[key])) return true;
      }

      return false;
   };

   const authorizer = options.authorizer || staticUsersAuthorizer;
   const isAsync = options.authorizeAsync !== undefined ? !!options.authorizeAsync : false;
   const getResponseBody = ensureFunction(options.unauthorizedResponse, "");
   const realm = ensureFunction(options.realm);

   assert(
      typeof users === "object",
      `Expected an object for the basic auth users, found ${typeof users} instead`
   );
   assert(
      typeof authorizer === "function",
      `Expected a function for the basic auth authorizer, found ${typeof authorizer} instead`
   );

   return function authMiddleware(req: Request, res: Response, next: NextFunction) {
      function unauthorized() {
         if (challenge) {
            let challengeString = "Basic";
            const realmName = realm(req);

            if (realmName) challengeString += ` realm="${realmName}"`;

            res.set("WWW-Authenticate", challengeString);
         }

         // TODO: Allow response body to be JSON (maybe autodetect?)
         const response = getResponseBody(req);

         if (typeof response === "string") return res.status(401).send(response);

         return res.status(401).json(response);
      }
      function authorizerCallback(err: Record<string, string>, approved: boolean) {
         assert.ifError(err);

         if (approved) return next();

         return unauthorized();
      }
      const authentication = auth(req);

      if (!authentication) return unauthorized();
      const request = req as IBasicAuthedRequest;
      request.auth = {
         password: authentication.pass,
         user: authentication.name,
      };

      if (isAsync) return authorizer(authentication.name, authentication.pass, authorizerCallback);
      if (!authorizer(authentication.name, authentication.pass)) return unauthorized();

      return next();
   };
}

buildMiddleware.safeCompare = safeCompare;
export default buildMiddleware;
