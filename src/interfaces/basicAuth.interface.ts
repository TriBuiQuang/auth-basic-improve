import { Request } from "express";

/**
 * Object to represent user credentials extracted from a Basic Auth header.
 */
export interface Credentials {
   name: string;
   pass: string;
}

/**
 * Request type with an optional `authorization` header.
 */
export interface IRequestHeaderAuthorization extends Request {
   headers: { authorization?: string };
}
