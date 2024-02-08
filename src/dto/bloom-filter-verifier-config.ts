import { DynamicSLBloomFilterVC } from './dynamic-sl-bloom-filter.js';

/**
 * Configuration for the bloom filter verifier
 */
export interface BloomFilterVerifierConfig {
  timeCheck?: boolean;
  vc: DynamicSLBloomFilterVC;
}
