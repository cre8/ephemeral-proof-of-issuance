import { ContainerVC } from './container-vc.js';

/**
 * Defines the credential that is holding the status list.
 */
export interface DynamicBloomFilterVC extends ContainerVC {
  // First, GZIP-compressed, then base64 encoded values of a Bloom Filter.
  content: string;
  // how many elements should be included into the filter
  size: number;
  // what is the false positive rate for the filter
  falsePositive: number;
}
