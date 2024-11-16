import type { JWTPayload } from 'jose';

/**
 * Defines the credential that is issued be the holder and parsed to the verifier.
 */
export interface CredentialStatusTokenPayload extends JWTPayload {
  // MUST match the ID property of the Verifiable Credential the status is meant for
  sub: string;
  // MUST be a base64 encoded token valid at the time of issuance (iat) – the secret is computed at the time specified in the validFrom property
  token: string;
}
