import { groth16 } from "snarkjs";
import {
  prefetchMembershipArtifacts,
  type ProverArtifacts,
} from "./artifacts";

// G1/G2 encoding, public signal order, and vk.ic length rules are
// specified in docs/wire-format.md — that document is the single source
// of truth; do not describe the wire format here.

import { InvalidInputError } from "./errors.js";
import { FR_MODULUS } from "./identity.js";

/** Circuit public-signal input shape. */
export interface CircuitInput extends Record<string, unknown> {
  identityNullifier: bigint;
  identitySecret: bigint;
  pathElements: bigint[];
  pathIndices: number[];
  root: bigint;
  externalNullifier: bigint;
}

/** Groth16 proof bytes in the contract's wire format (see docs/wire-format.md §3). */
export interface ContractProof {
  a: Uint8Array;
  b: Uint8Array;
  c: Uint8Array;
}

/** Verification key bytes in the contract's wire format (see docs/wire-format.md §3-4). */
export interface ContractVerificationKey {
  alpha: Uint8Array;
  beta: Uint8Array;
  gamma: Uint8Array;
  delta: Uint8Array;
  ic: Uint8Array[];
}

/** Default tree depth matching circuits/config.json. */
const DEFAULT_TREE_LEVELS = 4;

/**
 * Validates a circuit input object before proving.
 * Throws InvalidInputError on malformed input.
 */
export function validateCircuitInput(
  input: CircuitInput,
  levels: number = DEFAULT_TREE_LEVELS,
): void {
  const pathElements = input.pathElements as bigint[] | undefined;
  const pathIndices = input.pathIndices as number[] | undefined;

  if (!Array.isArray(pathElements) || pathElements.length !== levels) {
    throw new InvalidInputError(`pathElements: expected ${levels}, got ${pathElements?.length ?? "undefined"}`);
  }
  if (!Array.isArray(pathIndices) || pathIndices.length !== levels) {
    throw new InvalidInputError(`pathIndices: expected ${levels}, got ${pathIndices?.length ?? "undefined"}`);
  }

  for (let i = 0; i < levels; i++) {
    if (pathIndices[i] !== 0 && pathIndices[i] !== 1) {
      throw new InvalidInputError(`pathIndices[${i}]: expected 0 or 1, got ${pathIndices[i]}`);
    }
  }

  for (const key of ["identityNullifier", "identitySecret", "root", "externalNullifier"]) {
    const val = input[key];
    if (typeof val !== "bigint" || val < 0n || val >= FR_MODULUS) {
      throw new InvalidInputError(`${key}: must be in [0, FR_MODULUS), got ${val}`);
    }
  }

  for (let i = 0; i < levels; i++) {
    const val = pathElements[i];
    if (typeof val !== "bigint" || val < 0n || val >= FR_MODULUS) {
      throw new InvalidInputError(`pathElements[${i}]: must be in [0, FR_MODULUS), got ${val}`);
    }
  }
}

export interface ProofResult {
  proof: unknown;
  publicSignals: string[];
  provingTimeMs: number;
  artifactDownloadTimeMs: number;
  totalTimeMs: number;
}

let artifactPromise: Promise<ProverArtifacts> | undefined;

function getArtifacts(): Promise<ProverArtifacts> {
  if (!artifactPromise) {
    artifactPromise = prefetchMembershipArtifacts();
  }
  return artifactPromise;
}

/**
 * Generates a membership proof using the already-downloaded binary circuit
 * artifacts. The proving timer intentionally starts after this await so that
 * network time is not reported as proving/compute time.
 */
export async function fullProve(
  input: CircuitInput,
): Promise<ProofResult> {
  const artifacts = await getArtifacts();

  const provingStartedAt = performance.now();
  const result = await groth16.fullProve(
    input as any,
    artifacts.wasm,
    artifacts.zkey,
  );
  const provingTimeMs = Math.max(0, performance.now() - provingStartedAt);

  return {
    ...result,
    provingTimeMs,
    artifactDownloadTimeMs: 0,
    totalTimeMs: provingTimeMs,
  };
}

export async function prove(
  input: CircuitInput,
): Promise<ProofResult> {
  return fullProve(input);
}

export { prefetchMembershipArtifacts } from "./artifacts";
export type { ProverArtifacts } from "./artifacts";
