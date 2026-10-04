import { createHash, timingSafeEqual } from "node:crypto";
import { closeSync, constants, fstatSync, openSync, readSync } from "node:fs";
import { isAbsolute } from "node:path";
import { z } from "zod";
import { SbpError } from "./sbp-contract";

const keyId = z.string().regex(/^[A-Za-z0-9_-]{1,32}$/);
const key = z.strictObject({
  id: keyId,
  sha256: z.string().regex(/^[a-f0-9]{64}$/),
});
export const sbpKeysSchema = z
  .strictObject({
    current: key.nullable(),
    next: key.nullable(),
    revoked: z.array(keyId).max(64),
    version: z.literal(1),
  })
  .refine(
    (keys) => !(keys.current && keys.next && keys.current.id === keys.next.id)
  );
export type SbpKeys = z.infer<typeof sbpKeysSchema>;

/** No cache: atomic operator replacement supports immediate next-request revocation. */
export function loadSbpKeys(): SbpKeys {
  const path = process.env.NAKAMA_SBP_WORKLOAD_KEYS_FILE;
  if (!(path && isAbsolute(path))) {
    throw new SbpError("unavailable");
  }
  let fd: number | undefined;
  try {
    fd = openSync(
      path,
      // biome-ignore lint/suspicious/noBitwiseOperators: POSIX open flags
      constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK
    );
    const stat = fstatSync(fd);
    // biome-ignore lint/suspicious/noBitwiseOperators: POSIX permission mask
    if (!stat.isFile() || stat.size > 16_384 || (stat.mode & 0o022) !== 0) {
      throw new Error("invalid_key_file");
    }
    const bytes = Buffer.alloc(16_385);
    const length = readSync(fd, bytes, 0, bytes.length, 0);
    if (length > 16_384) {
      throw new Error("invalid_key_file");
    }
    return sbpKeysSchema.parse(
      JSON.parse(bytes.subarray(0, length).toString("utf8"))
    );
  } catch {
    throw new SbpError("unavailable");
  } finally {
    if (fd !== undefined) {
      closeSync(fd);
    }
  }
}

export function authenticateSbp(header: string | null, keys: SbpKeys): string {
  const match =
    /^Bearer sbp1\.([A-Za-z0-9_-]{1,32})\.([A-Za-z0-9_-]{43})$/.exec(
      header ?? ""
    );
  const id = match?.[1] ?? "";
  const secret = match?.[2] ?? "";
  const canonical =
    Buffer.from(secret, "base64url").toString("base64url") === secret;
  const digest = createHash("sha256").update(secret).digest();
  let accepted: string | null = null;
  // Both slots always perform the same fixed-length comparison, even for unknown IDs.
  for (const slot of [keys.current, keys.next]) {
    const expected = slot ? Buffer.from(slot.sha256, "hex") : Buffer.alloc(32);
    const equal = timingSafeEqual(digest, expected);
    if (
      equal &&
      match &&
      canonical &&
      slot?.id === id &&
      !keys.revoked.includes(id)
    ) {
      accepted = slot.id;
    }
  }
  if (!accepted) {
    throw new SbpError("unauthorized");
  }
  return accepted;
}
