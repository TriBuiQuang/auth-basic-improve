import { Request } from "express";

export interface IBasicAuthedRequest extends Request {
   auth: { user: string; password: string };
}

/**
 * Function type for custom synchronous authorizer.
 */
export type AuthorizerFn = (username: string, password: string) => boolean;

/**
 * Function type for async authorizer with callback pattern.
 */
export type AsyncAuthorizerFn = (
   username: string,
   password: string,
   callback: (err: Error | null, result: boolean) => void,
) => void;

/**
 * Function type for generating a custom unauthorized response body.
 */
export type UnauthorizedResponseFn = (req: IBasicAuthedRequest) => string | Record<string, unknown>;

/**
 * Function type for generating a dynamic realm string.
 */
export type RealmFn = (req: Request) => string | undefined;

export interface IbuildMiddleware {
   challenge?: boolean;
   users?: Record<string, string>;
   authorizeAsync?: boolean;
   unauthorizedResponse?: string | Record<string, unknown> | UnauthorizedResponseFn;
   authorizer?: AuthorizerFn | AsyncAuthorizerFn;
   realm?: string | RealmFn;
}
