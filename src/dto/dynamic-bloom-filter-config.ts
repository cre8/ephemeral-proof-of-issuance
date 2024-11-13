import { ContainerConfig } from './container-config.js';

export interface DynamicBloomFilterConfig extends ContainerConfig {
  // posibliity of a false positive event
  falsePositive?: number;
  // size of the list
  size?: number;
}
