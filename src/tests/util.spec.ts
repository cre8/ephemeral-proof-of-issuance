import { generateKeyPair } from 'jose';
import { describe, expect, it } from 'vitest';
import { DEFAULT_HASH_FUNCTION } from '../const.js';
import type { ContainerVCPayload } from '../dto/container-vc-payload.js';
import { signVc } from '../util.js';

describe('util', () => {
  it('sign a vc', async () => {
    const alg = 'ES256';
    const { privateKey } = await generateKeyPair(alg);
    const date = new Date().getTime();
    const vc: ContainerVCPayload = {
      jti: '',
      iss: '',
      iat: date,
      exp: date,
      content: '',
      hashFunction: DEFAULT_HASH_FUNCTION,
    };
    const sign = await signVc(privateKey, vc, { alg });
    // Can we check if the signature is valid?
    expect(sign).toBeDefined();
  });
});
