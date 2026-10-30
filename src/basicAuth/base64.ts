type Uint8ArrayWithBase64 = typeof Uint8Array & {
   fromBase64?: (str: string) => Uint8Array;
};

type BufferLike = {
   from(
      input: string,
      encoding: "base64" | "utf-8",
   ): { toString(encoding: "utf-8" | "base64"): string };
};

/* eslint-disable no-undef */
/**
 * GlobalTextEncoder — minimal interface matching Node.js global TextEncoder.
 * Available as a global in Node.js 16+.
 */
declare const TextEncoder: {
   new (): { encode(str: string): Uint8Array };
};

/**
 * GlobalTextDecoder — minimal interface matching Node.js global TextDecoder.
 * Available as a global in Node.js 16+.
 */
declare const TextDecoder: {
   new (label?: string): { decode(bytes: Uint8Array): string };
};
/* eslint-enable no-undef */

export const base64 = (() => {
   if (typeof Buffer !== "undefined") {
      return {
         decode: (str: string) => Buffer.from(str, "base64").toString("utf-8"),
         encode: (str: string) => Buffer.from(str, "utf-8").toString("base64"),
      };
   }

   const textEncoder = new TextEncoder();
   const textDecoder = new TextDecoder();
   const NodeBuffer = globalThis.Buffer as BufferLike | undefined;

   return {
      decode: (str: string) => {
         if (NodeBuffer) {
            return NodeBuffer.from(str, "base64").toString("utf-8");
         }
         const bytes = (Uint8Array as Uint8ArrayWithBase64).fromBase64!(str);
         return textDecoder.decode(bytes);
      },
      encode: (str: string) => {
         const bytes = textEncoder.encode(str);
         return (bytes as unknown as { toBase64: () => string }).toBase64();
      },
   };
})();
