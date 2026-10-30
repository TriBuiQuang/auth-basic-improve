import { timingSafeEqual } from "crypto";

import type { Request, Response, NextFunction } from "express";

import { auth, Credentials } from "../basicAuth";
import type {
   AsyncAuthorizerFn,
   AuthorizerFn,
   IbuildMiddleware,
   PromiseAuthorizerFn,
   RealmFn,
} from "../interfaces/expressBasicAuth.interface";

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

   // Always compute full comparison to prevent timing attacks.
   // When lengths differ, pad the shorter buffer so timingSafeEqual
   // still runs the full comparison — the XOR result will differ,
   // guaranteeing a `false` return without leaking length info.
   const maxLen = Math.max(userInputLength, secretLength);

   // Build padded buffers using Buffer.allocUnsafe + copy to avoid Buffer.concat
   // type errors. Buffer.concat returns Buffer with ArrayBufferLike .buffer,
   // which is incompatible with Uint8Array<ArrayBuffer> expected by
   // timingSafeEqual. Using Buffer.allocUnsafe + copy avoids this.
   const bufUser = Buffer.allocUnsafe(maxLen);
   Buffer.from(userInput, "utf8").copy(bufUser as unknown as Uint8Array, 0, 0, maxLen);
   const bufSecret = Buffer.allocUnsafe(maxLen);
   Buffer.from(secret, "utf8").copy(bufSecret as unknown as Uint8Array, 0, 0, maxLen);

   // Convert to Uint8Array for timingSafeEqual compatibility.
   // Buffer.buffer is ArrayBufferLike (includes SharedArrayBuffer),
   // which is incompatible with Uint8Array<ArrayBuffer> expected by
   // timingSafeEqual. Explicitly cast .buffer to ArrayBuffer to create
   // a fresh ArrayBuffer-backed Uint8Array copy.
   const userInputBytes = new Uint8Array(
      bufUser.buffer as ArrayBuffer,
      bufUser.byteOffset,
      bufUser.byteLength,
   );
   const secretBytes = new Uint8Array(
      bufSecret.buffer as ArrayBuffer,
      bufSecret.byteOffset,
      bufSecret.byteLength,
   );

   // timingSafeEqual always compares all bytes — length mismatch is
   // hidden by the padding (0x00 vs actual bytes), so timing is constant.
   const match = timingSafeEqual(userInputBytes, secretBytes);

   // If original lengths differed, the padded bytes won't match anyway,
   // but we explicitly enforce this to handle the edge case cleanly.
   return match && userInputLength === secretLength;
};

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

   if (typeof option !== "function")
      return (() => option as string) as (...args: unknown[]) => string;

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

   // Clone users object to prevent mutation between requests (security hardening)
   const users: Record<string, string> = { ...options.users };

   const staticUsersAuthorizer = (username: string, password: string): boolean => {
      const keys = Object.keys(users);
      for (let i = 0; i < keys.length; i += 1) {
         const key = keys[i];
         if (safeCompare(username, key) && safeCompare(password, users[key])) return true;
      }

      return false;
   };

   const authorizer: AuthorizerFn | AsyncAuthorizerFn = options.authorizer
      ? (options.authorizer as AuthorizerFn | AsyncAuthorizerFn)
      : staticUsersAuthorizer;
   const isAsync = typeof options.authorizeAsync === "boolean" ? options.authorizeAsync : false;
   const getResponseBody = ensureFunction(
      options.unauthorizedResponse as string | ((...args: unknown[]) => unknown),
      "",
   ) as
      ((...args: unknown[]) => string | Record<string, unknown>) | ((...args: unknown[]) => string);
   const realm = ensureFunction(options.realm as string | ((...args: unknown[]) => unknown)) as (
      ...args: unknown[]
   ) => string | undefined;

   if (typeof users !== "object") {
      throw new Error(`Expected an object for the basic auth users, found ${typeof users} instead`);
   }
   if (typeof authorizer !== "function") {
      throw new Error(
         `Expected a function for the basic auth authorizer, found ${typeof authorizer} instead`,
      );
   }

   return function authMiddleware(
      req: Request,
      res: Response,
      next: NextFunction,
   ): void | Promise<void> {
      function unauthorized() {
         if (challenge) {
            let challengeString = "Basic";
            const realmName = (realm as RealmFn)(req);

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

      function authorizerCallback(err: Error | null, approved: boolean): void {
         // Properly propagate errors through Express error-handling middleware
         if (err) return next(err);

         if (approved) return next();

         return unauthorized();
      }

      const authentication: Credentials | undefined = auth(req);

      if (!authentication) return unauthorized();

      // Attach parsed credentials to the request object.
      // The `auth` property is declared via module augmentation in `express.d.ts`,
      // so this is type-safe without any `as` assertions.
      req.auth = {
         password: authentication.pass,
         user: authentication.name,
      };

      if (isAsync) {
         // Callback-based async authorizer (3 args)
         return (
            authorizer as (
               username: string,
               password: string,
               cb: (err: Error | null, result: boolean) => void,
            ) => void
         )(authentication.name, authentication.pass, authorizerCallback);
      }

      // For sync and Promise-based authorizers, call with 2 args.
      // We narrow the type by checking the return value at runtime.
      const result: boolean | Promise<boolean> = (authorizer as AuthorizerFn | PromiseAuthorizerFn)(
         authentication.name,
         authentication.pass,
      );

      // Detect Promise-based async authorizers by checking if the result is a Promise
      if (result instanceof Promise) {
         return (result as Promise<boolean>).then(
            (approved) => {
               if (approved) return next();
               return unauthorized();
            },
            (err: unknown) => next(err),
         );
      }

      // Synchronous authorizer
      if (!result) return unauthorized();

      return next();
   };
}

buildMiddleware.safeCompare = safeCompare;
export default buildMiddleware;
