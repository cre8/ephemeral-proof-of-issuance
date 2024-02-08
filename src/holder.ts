import { randomUUID } from 'crypto';
import { type CredentialStatusToken } from './dto/credential-status-token.js';
import { hmac } from './util.js';
import { type CredentialStatusSecretVc } from './dto/credential-status-secret.js';

export async function createCredentialStatusToken(
  credentialStatusSecretVc: CredentialStatusSecretVc,
  issuer: string
): Promise<CredentialStatusToken> {
  const issuanceDate = new Date();
  const expirationDate = new Date(credentialStatusSecretVc.issuanceDate);
  // add the duration to the expiration date until we got a timestamp that is in the future
  while (expirationDate.getTime() < new Date().getTime()) {
    expirationDate.setSeconds(
      expirationDate.getSeconds() +
        credentialStatusSecretVc.credentialSubject.duration
    );
  }
  const token = await hmac(
    credentialStatusSecretVc.credentialSubject.duration.toString(),
    credentialStatusSecretVc.credentialSubject.secret,
    credentialStatusSecretVc.credentialSubject.hmacFunction
  );
  return {
    '@context': ['https://www.w3.org/2018/credentials/v1'],
    type: [
      'VerifiableCredential',
      'VerifiableAttestation',
      'CredentialStatusToken',
    ],
    id: randomUUID(),
    credentialSubject: {
      id: credentialStatusSecretVc.credentialSubject.id,
      token,
    },
    issuanceDate: issuanceDate.toISOString(),
    validFrom: issuanceDate.toISOString(),
    validUntil: expirationDate.toISOString(),
    expirationDate: expirationDate.toISOString(),
    issuer,
    credentialSchema: {
      // TODO set schema url
      id: '',
      type: 'FullJsonSchemaValidator2021',
    },
  };
}
