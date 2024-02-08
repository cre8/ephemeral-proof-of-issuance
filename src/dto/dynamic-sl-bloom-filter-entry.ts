import { ListPurpose } from './dynamic-sl-bloom-filter.js';

/**
 * Defines a VC that uses the DynamicSLBloomFilter strategy for the status list.
 */
export interface DynamicSLBloomFilterEntry {
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
    // MUST be "DynamicSLBloomFilterEntry"
    type: 'DynamicSLBloomFilterEntry';
    // MUST be revocation or suspension
    purpose: ListPurpose;
    // Defines the VC revocation id. base64 encoded SHA256 hash of the UTF-8 encoded vc.id
    index: string;
    // URL referencing the DynamicSLBloomFilter credential
    credential: string;
  };
}
