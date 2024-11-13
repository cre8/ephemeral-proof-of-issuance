import { exportJWK, generateKeyPair } from 'jose';
import { describe, expect, it } from 'vitest';
import {
  DEFAULT_FALSE_POSITIVE,
  DEFAULT_HASH_FUNCTION,
  DEFAULT_SIZE,
} from '../const.js';
import type { DynamicBloomFilterVC } from '../dto/dynamic-bloom-filter.js';
import { signVc } from '../util.js';

describe('util', () => {
  it('sign a vc', async () => {
    const alg = 'ES256';
    const { privateKey } = await generateKeyPair(alg);
    const date = new Date().getTime();
    const vc: DynamicBloomFilterVC = {
      jti: '',
      iss: '',
      iat: date,
      exp: date,
      content: '',
      hashFunction: DEFAULT_HASH_FUNCTION,
      falsePositive: DEFAULT_FALSE_POSITIVE,
      size: DEFAULT_SIZE,
    };
    const sign = await signVc(privateKey, vc, { alg });
    // Can we check if the signature is valid?
    expect(sign).toBeDefined();
  });
});
