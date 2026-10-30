import { auth, parse, format } from "./basicAuth/index";
import { safeCompare } from "./expressBasicAuth/index";
import buildMiddleware from "./expressBasicAuth/index";

export { auth, parse, format } from "./basicAuth/index";
export type { Credentials, IRequestHeaderAuthorization } from "./basicAuth/index";
export { safeCompare } from "./expressBasicAuth/index";
export { default as buildMiddleware } from "./expressBasicAuth/index";
export type {
   IBasicAuthedRequest,
   IbuildMiddleware,
   AuthorizerFn,
   AsyncAuthorizerFn,
   PromiseAuthorizerFn,
   UnauthorizedResponseFn,
   RealmFn,
} from "./interfaces/expressBasicAuth.interface";

export default {
   auth,
   buildMiddleware,
   format,
   parse,
   safeCompare,
};
