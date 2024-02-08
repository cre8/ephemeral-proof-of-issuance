import { HMACFunctionName } from '../util.js';
import { VC } from './vc.js';

/**
 * The Credential Status Secret carries a secret, which the issuer shares with the Holder, who transforms it into a token. DynamicSLBloomFilter strategy uses the secret as a seed.
 */
export interface CredentialStatusSecretVc extends VC {
  // MUST contain “CredentialStatusSecret”
  type: [
    'VerifiableCredential',
    'VerifiableAttestation',
    'CredentialStatusSecret'
  ];
  credentialSubject: {
    // MUST match the ID property of the associated Verifiable Credential
    id: string;
    // MUST be a base64 encoded seed secret used to compute the time-based password token. This must not be shared with anyone and decoded before use.
    secret: string;
    // Duration the token is valid at maximum, used in the algorithm to calculate new tokens. Default is 3600 (1 hour)
    duration: number;
    // Hash-based message authentication code function, default is HMAC-SHA256
    hmacFunction: HMACFunctionName;
  };
}
