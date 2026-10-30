import { Request } from "express";

import { base64 } from "./base64";
import { Credentials, IRequestHeaderAuthorization } from "../interfaces/basicAuth.interface";

export type { Credentials, IRequestHeaderAuthorization };

/*!\
 * basic-auth
 * Copyright(c) 2013 TJ Holowaychuk
 * Copyright(c) 2014 Jonathan Ong
 * Copyright(c) 2015-2016 Douglas Christopher Wilson
 * MIT Licensed
 */

/**
 * RegExp for basic auth credentials
 *
 * credentials = auth-scheme 1*SP token68
 * auth-scheme = "Basic" ; case insensitive
 * token68     = 1*( ALPHA / DIGIT / "-" / "." / "_" / "~" / "+" / "/" ) *"="
 * @private
 */
const CREDENTIALS_REGEXP = /^ *(?:[Bb][Aa][Ss][Ii][Cc]) +([A-Za-z0-9._~+/-]+=*) *$/;

/**
 * RegExp for RFC 5234 CTL characters (US-ASCII 0-31 and 127).
 * @private
 */
const CONTROL_CHARS_REGEXP = /[\x00-\x1F\x7F]/;

/**
 * Extracts the `Authorization` header value from a request object.
 *
 * @param req - The request object with headers.
 * @returns The authorization header string, or `undefined` if not present.
 * @private
 */
const getAuthorization = (req: IRequestHeaderAuthorization): string | undefined => {
   if (!req.headers || typeof req.headers !== "object") {
      return undefined;
   }

   return req.headers.authorization as string | undefined;
};

/**
 * Parses a base64-encoded Basic Authentication string into `{ name, pass }`.
 *
 * Expects the format `Basic <base64-encoded-credentials>`, where credentials
 * are `username:password` encoded in base64.
 *
 * @param string - The raw Authorization header value (e.g., `"Basic Zm9vOmJhcg=="`).
 * @returns An object with `name` and `pass` properties, or `undefined` if the
 *          string is malformed, lacks a colon separator, or has an invalid scheme.
 *
 * @example
 * ```typescript
 * const creds = parse("Basic Zm9vOmJhcg==");
 * // Returns: { name: "foo", pass: "bar" }
 * ```
 */
export const parse = (string: string): Credentials | undefined => {
   if (typeof string !== "string") {
      throw new TypeError("Expected a string");
   }

   // parse header
   const match = CREDENTIALS_REGEXP.exec(string);
   if (!match) return undefined;

   // decode user pass
   const userPass = base64.decode(match[1]);
   const colonIndex = userPass.indexOf(":");
   if (colonIndex === -1) return undefined;

   return {
      name: userPass.slice(0, colonIndex),
      pass: userPass.slice(colonIndex + 1),
   };
};

/**
 * Formats credentials into a Basic Authentication header string.
 *
 * Encodes `name:pass` as base64 and prefixes with `"Basic "`.
 * Validates that:
 * - `name` and `pass` are strings
 * - `name` does not contain a colon (per RFC 7617)
 * - Neither contains control characters (US-ASCII 0-31, 127)
 *
 * @param credentials - An object with `name` and `pass` string properties.
 * @returns A valid Basic Authentication header string (e.g., `"Basic Zm9vOmJhcg=="`).
 *
 * @throws {TypeError} If credentials is invalid, contains a colon in `name`,
 *                    or contains control characters.
 *
 * @example
 * ```typescript
 * const header = format({ name: "foo", pass: "bar" });
 * // Returns: "Basic Zm9vOmJhcg=="
 * ```
 */
export const format = (credentials: Credentials): string => {
   if (typeof credentials !== "object" || credentials === null) {
      throw new TypeError("Expected an object");
   }

   if (typeof credentials.name !== "string" || typeof credentials.pass !== "string") {
      throw new TypeError('Object must have string properties "name" and "pass"');
   }

   // RFC 7617 disallows colon in username
   if (credentials.name.includes(":")) {
      throw new TypeError('Object "name" must not contain a colon');
   }

   const str = credentials.name + ":" + credentials.pass;

   if (CONTROL_CHARS_REGEXP.test(str)) {
      throw new TypeError('Object "name" and "pass" must not contain control characters');
   }

   return "Basic " + base64.encode(str);
};

/**
 * Extracts and parses the `Authorization` header from an Express request.
 *
 * Reads the `Authorization` header, validates the Basic scheme, and returns
 * parsed `{ name, pass }` credentials. Returns `undefined` if no header is
 * present or if the header is malformed.
 *
 * @param req - An Express request object.
 * @returns An object with `name` and `pass` properties, or `undefined` if
 *          no valid Basic Auth header is found.
 *
 * @throws {TypeError} If `req` is null, undefined, or not an object.
 *
 * @example
 * ```typescript
 * app.get("/protected", (req, res) => {
 *    const creds = auth(req);
 *    if (!creds) return res.status(401).send("Unauthorized");
 *    console.log(creds.name); // "foo"
 *    console.log(creds.pass); // "bar"
 *    res.send("Authenticated!");
 * });
 * ```
 */
export const auth = (req: Request): Credentials | undefined => {
   if (!req) throw new TypeError("argument req is required");

   if (typeof req !== "object") throw new TypeError("argument req is required to be an object");

   // Get header
   const header = getAuthorization(req as IRequestHeaderAuthorization);
   if (typeof header !== "string") return undefined;

   // Parse header
   return parse(header);
};
