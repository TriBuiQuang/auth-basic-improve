import { describe, it } from "@jest/globals";

/**
 * GlobalTextDecoder — minimal interface matching Node.js global TextDecoder.
 * Available as a global in Node.js 16+.
 */
declare const TextDecoder: {
   new (label?: string): { decode(bytes: Uint8Array): string };
};

type BufferLike = {
   from(
      input: string,
      encoding: "base64" | "utf-8",
   ): { toString(encoding: "utf-8" | "base64"): string };
};

const NodeBuffer = globalThis.Buffer as BufferLike | undefined;

const textDecoder = new TextDecoder("utf-8");

function decodeBase64WithNodeBuffer(str: string): string {
   return NodeBuffer!.from(str, "base64").toString("utf-8");
}

function decodeBase64WithAtob(str: string): string {
   const binary = atob(str);
   return textDecoder.decode(Uint8Array.from(binary, (char) => char.charCodeAt(0)));
}

const hasNodeBuffer = typeof NodeBuffer?.from === "function";

const payloads = [
   {
      decoded: "user:password",
      name: "short username/password",
   },
   {
      decoded: "api-client-42:sample-token-not-a-secret",
      name: "common API style credential",
   },
   {
      decoded: "service-account:7f2d9c31f7f14131a65d5315f2dbdb34dc5ddacb4f57b74a04a066f53f8e92bf",
      name: "long token-like password",
   },
].map((payload) => ({
   ...payload,
   encoded: NodeBuffer!.from(payload.decoded, "utf-8").toString("base64"),
}));

// Sanity check that all decoding methods produce the same results before benchmarking
for (const payload of payloads) {
   if (decodeBase64WithAtob(payload.encoded) !== payload.decoded) {
      throw new Error(`atob decode failed for ${payload.name}`);
   }

   if (hasNodeBuffer && decodeBase64WithNodeBuffer(payload.encoded) !== payload.decoded) {
      throw new Error(`Buffer decode failed for ${payload.name}`);
   }
}

describe("decode base64 for basic-auth payloads", () => {
   for (const payload of payloads) {
      describe(payload.name, () => {
         if (hasNodeBuffer) {
            it("Buffer.from(base64).toString(utf-8)", () => {
               decodeBase64WithNodeBuffer(payload.encoded);
            });
         }

         it("atob + Uint8Array.from + TextDecoder", () => {
            decodeBase64WithAtob(payload.encoded);
         });
      });
   }
});
