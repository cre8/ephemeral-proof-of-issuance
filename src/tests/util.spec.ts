import { exportJWK, generateKeyPair } from 'jose';
import { signVc } from '../util';
import { DynamicSLBloomFilter2023VC } from '../dto/dynamic-sl-bloom-filter-2023';

describe('util', () => {
  it('sign a vc', async () => {
    const alg = 'ES256';
    const { privateKey } = await generateKeyPair(alg);
    const date = '2023-09-28T09:14:17.555Z';
    const vc: DynamicSLBloomFilter2023VC = {
      '@context': ['https://www.w3.org/2018/credentials/v1'],
      type: [
        'VerifiableCredential',
        'VerifiableAttestation',
        'DynamicSLBloomFilter2023',
      ],
      id: '',
      issuer: '',
      issuanceDate: date,
      expirationDate: date,
      validFrom: date,
      validUntil: date,
      credentialSubject: {
        // not clear why we need the fragment here. Can maybe be removed
        id: '',
        purpose: 'revocation',
        content: '',
      },
      credentialSchema: {
        id: '',
        type: 'FullJsonSchemaValidator2021',
      },
    };
    const sign = await signVc(await exportJWK(privateKey), vc, alg);
    // Can we check if the signature is valid?
    expect(sign).toBeDefined();
  });
});
