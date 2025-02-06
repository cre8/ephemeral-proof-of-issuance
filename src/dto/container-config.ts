import type { HMACFunctionName, HashFunctionName } from '../util.js';

export interface ContainerConfig {
  // id of the status list
  id: string;
  // issuer of the list
  issuer: string;
  // period in seconds a status list is valid
  epoch?: number;
  // hash function used
  hashFunction?: HashFunctionName;
  // hmac function used
  hmacFunction?: HMACFunctionName;
}
