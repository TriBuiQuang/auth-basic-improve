import * as authBasicImprove from "./app";

export * from "./app";
export { parse, format, Credentials } from "./basicAuth/index";
export type {
   IAuthObject,
   TAuth,
   IRequestHeaderAuthorization,
} from "./interfaces/basicAuth.interface";
export type {
   IBasicAuthedRequest,
   IbuildMiddleware,
} from "./interfaces/expressBasicAuth.interface";

export default authBasicImprove;
