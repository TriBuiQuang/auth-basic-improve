import { Request } from "express";

import { IRequestHeaderAuthorization, TAuth } from "@/interfaces/basicAuth.interface";
import { IBasicAuthedRequest } from "@/interfaces/expressBasicAuth.interface";
/*!
 * basic-auth
 * MIT Licensed
 */

/**
 * RegExp for basic auth credentials
 *
 * credentials = auth-scheme 1*SP token68
 * auth-scheme = "Basic" ; case insensitive
 * token68     = 1*( ALPHA / DIGIT / "-" / "." / "_" / "~" / "+" / "/" ) *"="
 */
const CREDENTIALS_REGEXP = /^ *(?:[Bb][Aa][Ss][Ii][Cc]) +([A-Za-z0-9._~+/-]+=*) *$/;

/**
 * RegExp for basic auth user/pass
 *
 * user-pass   = userid ":" password
 * userid      = *<TEXT excluding ":">
 * password    = *TEXT
 */
const USER_PASS_REGEXP = /^([^:]*):(.*)$/;

/**
 * Decode base64 string.
 */
const decodeBase64 = (str: string) => Buffer.from(str, "base64").toString();

/**
 * Get the Authorization header from request object.
 */
const getAuthorization = (req: IRequestHeaderAuthorization): string => {
   if (!req.headers || typeof req.headers !== "object") {
      return "";
   }

   return req.headers.authorization;
};

/**
 * Parse basic auth to object.
 */
export const parse = (str?: string): any => {
   if (typeof str !== "string") return "";

   // parse header
   const match = CREDENTIALS_REGEXP.exec(str);

   if (!match) return "";

   // decode user pass
   const userPass = USER_PASS_REGEXP.exec(decodeBase64(match[1]));

   if (!userPass) return "";

   // return credentials object
   return { name: userPass[1], pass: userPass[2] };
};

/**
 * Parse the Authorization header field of a request.
 *
 * @param {object} req
 * @return {object} with .name and .pass
 */
export const auth = (req?: Request): any => {
   if (!req) throw new TypeError("argument req is required");

   if (typeof req !== "object") throw new TypeError("argument req is required to be an object");

   // Get header
   const header = getAuthorization(req as IRequestHeaderAuthorization);
   // console.log("parse", typeof parse(header));

   // Parse header
   return parse(header);
};
