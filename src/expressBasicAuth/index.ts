import assert from "assert";
import { timingSafeEqual } from "crypto";

import type { Request, Response, NextFunction } from "express";

import { auth, Credentials } from "../basicAuth";
import type { IbuildMiddleware } from "../interfaces/expressBasicAuth.interface";

/**
 * Performs a timing-safe comparison of two strings using `crypto.timingSafeEqual`.
 *
 * This function prevents timing attacks by ensuring comparison takes constant time
 * regardless of where strings differ. Both strings must have the same byte length;
 * if lengths differ, the function returns `false` immediately without leaking
 * information about which string is "longer".
 *
 * @param userInput - The first string to compare (user input).
 * @param secret - The second string to compare (stored secret).
 * @returns `true` if both strings are identical and have the same length; `false` otherwise.
 *
 * @example
 * ```typescript
 * const isValid = safeCompare("myToken", "myToken"); // true
 * const isInvalid = safeCompare("wrong", "correct"); // false
 * ```
 */
export const safeCompare = (userInput: string, secret: string): boolean => {
   const userInputLength = Buffer.byteLength(userInput);
   const secretLength = Buffer.byteLength(secret);

   // Early exit on length mismatch — no constant-time concern since we reject immediately
   if (userInputLength !== secretLength) return false;

   const userInputBuffer = Buffer.from(userInput, "utf8");
   const secretBuffer = Buffer.from(secret, "utf8");

   return timingSafeEqual(new Uint8Array(userInputBuffer), new Uint8Array(secretBuffer));
};

/**
 * Type guard to check if a value is a function.
 *
 * @param value - The value to check.
 * @returns `true` if the value is a function.
 */
const isFunction = (value: unknown): value is (...args: unknown[]) => unknown =>
   typeof value === "function";

/**
 * Normalizes an option into a function that returns a value.
 *
 * - If `option` is `undefined`, returns a function that returns `defaultValue`.
 * - If `option` is a non-function value, returns a function that returns that value.
 * - If `option` is already a function, returns it as-is.
 *
 * @param option - The option to normalize (may be `undefined`, a value, or a function).
 * @param defaultValue - The default value to use when `option` is `undefined`.
 * @returns A function that resolves to the appropriate value.
 *
 * @example
 * ```typescript
 * // Returns () => "default realm"
 * const fn = ensureFunction(undefined, "default realm");
 *
 * // Returns () => "static realm"
 * const fn2 = ensureFunction("static realm");
 *
 * // Returns the original function
 * const fn3 = ensureFunction((req) => `realm for ${req.url}`);
 * ```
 */
const ensureFunction = (
   option?: string | ((...args: unknown[]) => unknown),
   defaultValue?: string,
): ((...args: unknown[]) => string | undefined) => {
   if (option === undefined)
      return (() => defaultValue) as (...args: unknown[]) => string | undefined;

   if (!isFunction(option)) return (() => option as string) as (...args: unknown[]) => string;

   return option as (...args: unknown[]) => string;
};

/**
 * Creates an Express authentication middleware with configurable options.
 *
 * Supports static user validation, custom synchronous/async authorizers,
 * timing-safe comparisons, configurable challenge headers, and custom response bodies.
 *
 * @param options - Configuration options for the middleware.
 * @returns An Express middleware function `(req, res, next) => void`.
 *
 * @example
 * ```typescript
 * const authMiddleware = buildMiddleware({
 *    challenge: false,
 *    users: { Admin: "secret1234" },
 * });
 *
 * app.get("/admin", authMiddleware, (req, res) => {
 *    res.send("Welcome, Admin!");
 * });
 * ```
 */
function buildMiddleware(options: IbuildMiddleware) {
   const challenge = typeof options.challenge === "boolean" ? options.challenge : false;
   const users = options.users || {};

   const staticUsersAuthorizer = (username: string, password: string): boolean => {
      const keys = Object.keys(users);
      for (let i = 0; i < keys.length; i += 1) {
         const key = keys[i];
         if (safeCompare(username, key) && safeCompare(password, users[key])) return true;
      }

      return false;
   };

   const authorizer = options.authorizer
      ? (options.authorizer as (username: string, password: string) => boolean)
      : staticUsersAuthorizer;
   const isAsync = typeof options.authorizeAsync === "boolean" ? options.authorizeAsync : false;
   const getResponseBody = ensureFunction(
      options.unauthorizedResponse as string | ((...args: unknown[]) => unknown),
      "",
   );
   const realm = ensureFunction(options.realm as string | ((...args: unknown[]) => unknown));

   assert(
      typeof users === "object",
      `Expected an object for the basic auth users, found ${typeof users} instead`,
   );
   assert(
      typeof authorizer === "function",
      `Expected a function for the basic auth authorizer, found ${typeof authorizer} instead`,
   );

   return function authMiddleware(req: Request, res: Response, next: NextFunction): void {
      function unauthorized() {
         if (challenge) {
            let challengeString = "Basic";
            const realmName = (realm as (...args: unknown[]) => string | undefined)(req);

            if (realmName) challengeString += ` realm="${realmName}"`;

            res.set("WWW-Authenticate", challengeString);
         }

         const response = getResponseBody(req);

         if (typeof response === "string") {
            res.status(401).send(response);
         } else {
            res.status(401).json(response);
         }
      }

      function authorizerCallback(
         err: Error | null | Record<string, string>,
         approved: boolean,
      ): void {
         assert.ifError(err);

         if (approved) return next();

         return unauthorized();
      }

      const authentication: Credentials | undefined = auth(req);

      if (!authentication) return unauthorized();

      // Attach parsed credentials to the request object using Object.defineProperty
      // to properly extend the Request type without unsafe type assertions
      const authedReq = req as Request & { auth?: { user: string; password: string } };
      authedReq.auth = {
         password: authentication.pass,
         user: authentication.name,
      };

      if (isAsync)
         return (
            authorizer as (
               username: string,
               password: string,
               cb: (err: Error | null, result: boolean) => void,
            ) => void
         )(authentication.name, authentication.pass, authorizerCallback);

      if (!authorizer(authentication.name, authentication.pass)) return unauthorized();

      return next();
   };
}

buildMiddleware.safeCompare = safeCompare;
export default buildMiddleware;
