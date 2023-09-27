import { ListPurpose } from './dynamic-sl-bloom-filter-2023';

export interface DynamicSLBloomFilter2023Config {
  // id of the status list
  id: string;
  // issuer of the list
  issuer: string;
  // path where the schema is located. Required for the vc-issuer to validate the vc
  dynamicSLBloomFilter2023Schema: string;
  // purpose of the list
  purpose?: ListPurpose;
  // posibliity of a false positive event
  falsePositive?: number;
  // size of the list
  size?: number;
  // number of hash functions used
  nbHashes?: number;
  // period in seconds a status list is valid
  epoch?: number;
}
