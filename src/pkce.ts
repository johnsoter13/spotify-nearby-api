import crypto from "crypto";

export function generateCodeVerifier(length = 64) {
  return base64URLEncode(crypto.randomBytes(length));
}

export function generateCodeChallenge(verifier: string) {
  return base64URLEncode(crypto.createHash("sha256").update(verifier).digest());
}

export function randomState(length = 16) {
  return base64URLEncode(crypto.randomBytes(length));
}

function base64URLEncode(buffer: Buffer) {
  return buffer
    .toString("base64")
    .replace(/=/g, "")
    .replace(/\+/g, "-")
    .replace(/\//g, "_");
}