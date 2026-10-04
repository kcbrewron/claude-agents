/**
 * Key management: every calling agent's identity is an Ed25519 key pair.
 *
 * Why Ed25519? It's fast and compact, Workers' Web Crypto supports it natively,
 * and it has no parameters to get wrong (unlike RSA padding or ECDSA nonces).
 * Private keys live only in the owning Worker's secrets; the public half (a
 * JWK) is registered with the authorization server.
 */
import {
  calculateJwkThumbprint,
  exportJWK,
  generateKeyPair,
  importJWK,
  type CryptoKey,
  type JWK,
} from "jose";

export const ALG = "EdDSA";

export interface AgentKeyPair {
  privateJwk: JWK;
  publicJwk: JWK;
}

export async function generateAgentKey(): Promise<AgentKeyPair> {
  const { privateKey, publicKey } = await generateKeyPair(ALG, { crv: "Ed25519", extractable: true });
  const pub = await exportJWK(publicKey);
  const kid = await thumbprint(pub);
  return {
    privateJwk: { ...(await exportJWK(privateKey)), kid, alg: ALG },
    publicJwk: { ...pub, kid, alg: ALG, use: "sig" },
  };
}

/** RFC 7638 thumbprint: a stable ID for a public key that both sides compute independently. */
export function thumbprint(jwk: JWK): Promise<string> {
  return calculateJwkThumbprint({ kty: jwk.kty, crv: jwk.crv, x: jwk.x });
}

/** Strip a JWK down to its public members. */
export function publicPart(jwk: JWK): JWK {
  return { kty: jwk.kty, crv: jwk.crv, x: jwk.x };
}

export async function importPrivateKey(jwk: JWK): Promise<CryptoKey> {
  return (await importJWK(jwk, ALG)) as CryptoKey;
}

/** Import a public key that may have come over the wire, refusing anything unexpected. */
export async function importPublicKey(jwk: JWK): Promise<CryptoKey> {
  if (jwk?.kty !== "OKP" || jwk.crv !== "Ed25519" || typeof jwk.x !== "string") {
    throw new Error("only Ed25519 (OKP) public keys are accepted");
  }
  if ("d" in jwk) {
    // A JWK with "d" is a *private* key. Never accept one over the wire.
    throw new Error("JWK contains private key material");
  }
  return (await importJWK(publicPart(jwk), ALG)) as CryptoKey;
}
