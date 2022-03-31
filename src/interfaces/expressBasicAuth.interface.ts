import { Request } from "express";

export interface IBasicAuthedRequest extends Request {
   auth: { user: string; password: string };
}

export interface IbuildMiddleware {
   challenge?: boolean;
   users?: Record<string, string>;
   authorizeAsync?: boolean;
   unauthorizedResponse?: unknown;
   authorizer?: unknown;
   realm?: unknown;
}
