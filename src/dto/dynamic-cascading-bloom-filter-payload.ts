import { ContainerVCPayload } from './container-vc-payload.js';

/**
 * Defines the credential that is holding the status list.
 */
export interface DynamicCascadingBloomFilterVCPayload
  extends ContainerVCPayload {
  // First, GZIP-compressed, then base64 encoded values of a Bloom Filter.
  content: string[];
  // how many elements should be included into the filter
  size: number;
  // what is the false positive rate for the filter. Even when we set it to 0, we need to value to build the bloom filter.
  falsePositive: number;
}
