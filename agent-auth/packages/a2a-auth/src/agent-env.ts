import type { Fetcher } from "./client";
import { replayStore, type ReplayNamespace } from "./replay";
import type { VerifierOptions } from "./verifier";

/** Bindings every agent that *receives* calls needs. */
export interface ResourceServerEnv {
  AGENT_ID: string;
  SELF_URL: string;
  ISSUER: string;
  AUTH: Fetcher;
  REPLAY: ReplayNamespace;
}

/** Build verifier options from a request's bindings. */
export function verifierFromEnv(env: ResourceServerEnv): VerifierOptions {
  return {
    audience: env.AGENT_ID,
    selfUrl: env.SELF_URL,
    issuer: env.ISSUER,
    auth: env.AUTH,
    replay: replayStore(env.REPLAY, "dpop-proofs"),
  };
}
