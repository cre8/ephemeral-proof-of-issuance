import { ContainerVC } from './container-vc.js';

/**
 * Configuration for the bloom filter verifier
 */
export interface VerifierConfig<T extends ContainerVC> {
  timeCheck?: boolean;
  vc: T;
}
