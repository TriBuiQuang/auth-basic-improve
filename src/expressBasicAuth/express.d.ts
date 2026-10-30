import "express";

declare module "express" {
   interface Request {
      /**
       * Parsed Basic Auth credentials, attached by `buildMiddleware`.
       * Only available when the middleware has processed the request.
       */
      auth?: { user: string; password: string };
   }
}

/**
 * Request type with parsed Basic Auth credentials.
 */
export interface IBasicAuthedRequest extends Request {
   auth: { user: string; password: string };
}
