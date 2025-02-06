import type { ContainerVCPayload } from './container-vc-payload.js';

/**
 * Configuration for the bloom filter verifier
 */
export interface VerifierConfig<T extends ContainerVCPayload> {
  timeCheck?: boolean;
  vc: T;
}
