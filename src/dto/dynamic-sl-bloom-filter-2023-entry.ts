import { ListPurpose } from './dynamic-sl-bloom-filter-2023';

/**
 * Defines a VC that uses the DynamicSLBloomFilter2023 strategy for the status list.
 */
export interface DynamicSLBloomFilter2023Entry {
  '@context': ['https://www.w3.org/2018/credentials/v1'];
  id: string;
  type: ['VerifiableCredential', 'VerifiableAttestation'];
  issuer: string;
  credentialSubject: {
    id: string;
  };
  credentialStatus: {
    // Identifier for the status information.
    id: string;
    // MUST be "DynamicSLBloomFilter2023Entry"
    type: 'DynamicSLBloomFilter2023Entry';
    // MUST be revocation or suspension
    purpose: ListPurpose;
    // Defines the VC revocation id. base64 encoded SHA256 hash of the UTF-8 encoded vc.id
    index: string;
    // URL referencing the DynamicSLBloomFilter2023 credential
    credential: string;
  };
}
