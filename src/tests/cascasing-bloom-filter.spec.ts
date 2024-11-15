import { randomUUID } from 'node:crypto';
import { beforeAll, describe, expect, it } from 'vitest';
import {
  DEFAULT_EPOCH,
  DEFAULT_FALSE_POSITIVE,
  DEFAULT_SIZE,
} from '../const.js';
import { createCredentialStatusToken } from '../holder.js';
import { createSecret } from '../util.js';
import { DynamicCascadingBloomFilterConfig } from '../dto/dynamic-cascading-bloom-filter-config.js';
import { DynamicCascadingBloomFilter } from '../container/dynamic-cascading-bloom-filter.js';
import { CascadingBloomFilterVerifier } from '../verifier/cascadinbg-bloom-filter-verifier.js';
import { VcStatus } from '../dto/vc-status.js';

// issuer reference of the vc statuslist
const issuer = 'http://example.com';

async function init() {}

describe('cascading bloom list', () => {
  beforeAll(async () => {
    await init();
  });

  it('creates a list', () => {
    const config: DynamicCascadingBloomFilterConfig = {
      id: randomUUID(),
      issuer,
      epoch: DEFAULT_EPOCH,
      falsePositive: DEFAULT_FALSE_POSITIVE,
      size: 2000,
      cacheHashed: true,
    };
    const statuslist = new DynamicCascadingBloomFilter(config);
    expect(statuslist).toBeDefined();
  });

  it('is a value in the list', async () => {
    const amount = 100;

    const config: DynamicCascadingBloomFilterConfig = {
      id: randomUUID(),
      issuer,
      cacheHashed: true,
      size: 25,
    };
    const statuslist = new DynamicCascadingBloomFilter(config);

    const entries: VcStatus[] = [];
    for (let i = 0; i < amount; i++) {
      entries.push({
        s_id: randomUUID(),
        secret: createSecret(),
        valid: i % 2 === 0,
      });
    }
    for (const entry of entries) {
      entry.valid
        ? await statuslist.addValid(entry.s_id, entry.secret)
        : await statuslist.addInvalid(entry.s_id, entry.secret);
    }

    const id = randomUUID();
    const secret = createSecret();
    const credentialStatusVc = await statuslist.addValid(id, secret);
    const dynamicCascadingBloomFilterVC = await statuslist.createVcPayload();

    console.log(dynamicCascadingBloomFilterVC);

    const verifier = new CascadingBloomFilterVerifier({
      vc: dynamicCascadingBloomFilterVC,
    });
    const vcToken = await createCredentialStatusToken(
      credentialStatusVc,
      issuer
    );
    expect(await verifier.isValid(vcToken)).toBe(true);

    vcToken.token = 'invalidValue';
    expect(await verifier.isValid(vcToken)).toBe(false);
  });
});
