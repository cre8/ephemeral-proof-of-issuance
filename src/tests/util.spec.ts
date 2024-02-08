import { describe, it, expect } from 'vitest';
import { exportJWK, generateKeyPair } from 'jose';
import { signVc } from '../util.js';
import { DynamicSLBloomFilterVC } from '../dto/dynamic-sl-bloom-filter.js';
import {
  DEFAULT_FALSE_POSITIVE,
  DEFAULT_HASH_FUNCTION,
  DEFAULT_SIZE,
} from '../const.js';

describe('util', () => {
  it('sign a vc', async () => {
    const alg = 'ES256';
    const { privateKey } = await generateKeyPair(alg);
    const date = '2023-09-28T09:14:17.555Z';
    const vc: DynamicSLBloomFilterVC = {
      '@context': ['https://www.w3.org/2018/credentials/v1'],
      type: [
        'VerifiableCredential',
        'VerifiableAttestation',
        'DynamicSLBloomFilter',
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
        hashFunction: DEFAULT_HASH_FUNCTION,
        falsePositive: DEFAULT_FALSE_POSITIVE,
        size: DEFAULT_SIZE,
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
