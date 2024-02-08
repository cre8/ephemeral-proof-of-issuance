import { VC } from './vc.js';

/**
 * Defines the credential that is issued be the holder and parsed to the verifier.
 */
export interface CredentialStatusToken extends VC {
  // MUST contain "CredentialStatusToken"
  type: [
    'VerifiableCredential',
    'VerifiableAttestation',
    'CredentialStatusToken'
  ];
  // https://www.w3.org/TR/vc-data-model/#expiration
  // @deprecated will be deprecated according to the next version of the VC data model
  expirationDate: string;
  // we need to inform the verifier about the time the token is valid
  // https://www.w3.org/TR/vc-data-model-2.0/#validity-period
  validUntil: string;
  credentialSubject: {
    // MUST match the ID property of the Verifiable Credential the status is meant for
    id: string;
    // MUST be a base64 encoded token valid at the time of issuance (iat) – the secret is computed at the time specified in the validFrom property
    token: string;
  };
}
