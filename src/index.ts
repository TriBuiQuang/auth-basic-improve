import * as authBasicImprove from "./app";

export { auth } from "./basicAuth/index";
export { parse, format, Credentials } from "./basicAuth/index";
export type { Credentials as ICredentials, IRequestHeaderAuthorization } from "./basicAuth/index";
export type {
   IBasicAuthedRequest,
   IbuildMiddleware,
} from "./interfaces/expressBasicAuth.interface";

export default authBasicImprove;
