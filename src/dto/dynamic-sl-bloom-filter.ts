import { HashFunctionName } from '../util.js';
import { VC } from './vc.js';

export type ListPurpose = 'revocation' | 'suspension';

/**
 * Defines the credential that is holding the status list.
 */
export interface DynamicSLBloomFilterVC extends VC {
  // MUST contain "DynamicSLBloomFilter"
  type: [
    'VerifiableCredential',
    'VerifiableAttestation',
    'DynamicSLBloomFilter'
  ];
  // https://www.w3.org/TR/vc-data-model/#expiration
  // @deprecated will be deprecated according to the next version of the VC data model
  expirationDate: string;
  // https://www.w3.org/TR/vc-data-model-2.0/#validity-period
  validUntil: string;
  credentialSubject: {
    id: string;
    // Must be revocation or suspension
    purpose: ListPurpose;
    // First, GZIP-compressed, then base64 encoded values of a Bloom Filter.
    content: string;
    // Hashing function. SHA-256 MUST be used. Multiple inputs are simply concatenated.
    hashFunction: HashFunctionName | HashFunctionName[];
    // how many elements should be included into the filter
    size: number;
    // what is the false positive rate for the filter
    falsePositive: number;
  };
}
