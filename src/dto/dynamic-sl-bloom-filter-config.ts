import { HMACFunctionName, HashFunctionName } from '../util.js';
import { ListPurpose } from './dynamic-sl-bloom-filter.js';

export interface DynamicSLBloomFilterConfig {
  // id of the status list
  id: string;
  // issuer of the list
  issuer: string;
  // path where the schema is located. Required for the vc-issuer to validate the vc
  dynamicSLBloomFilterSchema: string;
  // purpose of the list
  purpose?: ListPurpose;
  // posibliity of a false positive event
  falsePositive?: number;
  // size of the list
  size?: number;
  // period in seconds a status list is valid
  epoch?: number;
  // hash function used
  hashFunction?: HashFunctionName;
  // hmac function used
  hmacFunction?: HMACFunctionName;
}
