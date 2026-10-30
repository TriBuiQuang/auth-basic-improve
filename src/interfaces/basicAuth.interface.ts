import { Request } from "express";

/**
 * Object to represent user credentials.
 */
export interface Credentials {
   name: string;
   pass: string;
}

/**
 * @deprecated Use Credentials instead. Kept for backward compatibility.
 */
export interface IAuthObject {
   name?: string;
   pass?: string;
}

export type TAuth = IAuthObject | string;

export interface IRequestHeaderAuthorization extends Request {
   headers: { authorization?: string };
}
