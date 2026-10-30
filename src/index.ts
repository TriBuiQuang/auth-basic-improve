import { auth, parse, format } from "./basicAuth/index";
import { safeCompare } from "./expressBasicAuth/index";
import buildMiddleware from "./expressBasicAuth/index";

export { auth, parse, format } from "./basicAuth/index";
export type { Credentials, IRequestHeaderAuthorization } from "./basicAuth/index";
export type {
   IBasicAuthedRequest,
   IbuildMiddleware,
   AuthorizerFn,
   AsyncAuthorizerFn,
   UnauthorizedResponseFn,
   RealmFn,
} from "./interfaces/expressBasicAuth.interface";

export { safeCompare } from "./expressBasicAuth/index";
export { default as buildMiddleware } from "./expressBasicAuth/index";

export default { auth, parse, format, safeCompare, buildMiddleware };
