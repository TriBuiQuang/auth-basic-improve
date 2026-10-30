/**
 * Base64 encode/decode utilities optimized for Node.js environments.
 * Since Node.js >= 22 is required, Buffer is always available.
 */
export const base64 = {
   decode: (str: string) => Buffer.from(str, "base64").toString("utf-8"),
   encode: (str: string) => Buffer.from(str, "utf-8").toString("base64"),
};
