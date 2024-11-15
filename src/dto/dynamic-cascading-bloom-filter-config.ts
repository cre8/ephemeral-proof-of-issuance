import { ContainerConfig } from './container-config.js';

export interface DynamicCascadingBloomFilterConfig extends ContainerConfig {
  // posibliity of a false positive event
  falsePositive?: number;
  // size of the list
  size?: number;
  // if true, the hashes will be stored in an array
  cacheHashed: boolean;
}
