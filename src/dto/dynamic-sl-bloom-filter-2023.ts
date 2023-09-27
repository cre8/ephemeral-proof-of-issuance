import { VC } from './vc';

export type ListPurpose = 'revocation' | 'suspension';

/**
 * Defines the credential that is holding the status list.
 */
export interface DynamicSLBloomFilter2023VC extends VC {
  // MUST contain "DynamicSLBloomFilter2023"
  type: [
    'VerifiableCredential',
    'VerifiableAttestation',
    'DynamicSLBloomFilter2023'
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
  };
}
