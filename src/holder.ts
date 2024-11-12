import type { CredentialStatusSecretVc } from './dto/credential-status-secret.js';
import type { CredentialStatusToken } from './dto/credential-status-token.js';
import { hmac } from './util.js';

/**
 * Create a credential status token
 * @param credentialStatusSecretVc VC issued by the issuer and included all relevant information
 * @param issuer issuer of the token
 * @returns payload for the credential status token
 */
export async function createCredentialStatusToken(
  credentialStatusSecretVc: CredentialStatusSecretVc,
  issuer: string
): Promise<CredentialStatusToken> {
  const issuanceDate = new Date();
  const expirationDate = new Date(credentialStatusSecretVc.iat);
  // add the duration to the expiration date until we got a timestamp that is in the future
  while (expirationDate.getTime() < new Date().getTime()) {
    expirationDate.setSeconds(
      expirationDate.getSeconds() + credentialStatusSecretVc.duration
    );
  }
  const token = await hmac(
    credentialStatusSecretVc.duration.toString(),
    credentialStatusSecretVc.secret,
    credentialStatusSecretVc.hmacFunction
  );
  return {
    sub: credentialStatusSecretVc.sub,
    token,
    iat: issuanceDate.getTime(),
    exp: expirationDate.getTime(),
    iss: issuer,
  };
}
