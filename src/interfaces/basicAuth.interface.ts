import { Request } from "express";

export interface IAuthObject {
   name?: string;
   pass?: string;
}

export type TAuth = IAuthObject | string;

export interface IRequestHeaderAuthorization extends Request {
   headers: { authorization: string };
}
