import { randomUUID } from 'node:crypto';
import { beforeAll, describe, expect, it } from 'vitest';
import { BloomFilterVerifier } from '../verifier/bloom-filter-verifier.js';
import {
  DEFAULT_EPOCH,
  DEFAULT_FALSE_POSITIVE,
  DEFAULT_SIZE,
} from '../const.js';
import type { CredentialStatusToken } from '../dto/credential-status-token.js';
import type { DynamicBloomFilterConfig } from '../dto/dynamic-bloom-filter-config.js';
import type { VcStatus } from '../dto/vc-status.js';
import { DynamicBloomFilter } from '../container/dynamic-bloom-filter.js';
import { createCredentialStatusToken } from '../holder.js';
import { createSecret, hash, hmac } from '../util.js';

// issuer reference of the vc statuslist
const issuer = 'http://example.com';

async function init() {}

describe('bloom list', () => {
  beforeAll(async () => {
    await init();
  });

  it('creates a list', () => {
    const config: DynamicBloomFilterConfig = {
      id: randomUUID(),
      issuer,
      epoch: DEFAULT_EPOCH,
      falsePositive: DEFAULT_FALSE_POSITIVE,
      size: DEFAULT_SIZE,
    };
    const statuslist = new DynamicBloomFilter(config);
    expect(statuslist).toBeDefined();
  });
  it('is a value in the list', async () => {
    const config: DynamicBloomFilterConfig = {
      id: randomUUID(),
      issuer,
    };
    const statuslist = new DynamicBloomFilter(config);
    const id = randomUUID();
    const secret = createSecret();
    const credentialStatusVc = await statuslist.addValid(id, secret);
    const dynamicBloomFilterVC = statuslist.createVcPayload();

    const verifier = new BloomFilterVerifier({
      vc: dynamicBloomFilterVC,
    });
    const vcToken = await createCredentialStatusToken(
      credentialStatusVc,
      issuer
    );
    expect(await verifier.isValid(vcToken)).toBe(true);

    vcToken.token = 'invalidValue';
    expect(await verifier.isValid(vcToken)).toBe(false);
  });

  it('check with an expired vc', async () => {
    const config: DynamicBloomFilterConfig = {
      id: randomUUID(),
      issuer,
      hashFunction: 'SHA-256',
      hmacFunction: 'SHA-256',
    };
    const statuslist = new DynamicBloomFilter(config);
    const id = randomUUID();
    const secret = createSecret();
    const credentialStatusVc = await statuslist.addValid(id, secret);
    const dynamicBloomFilterVC = statuslist.createVcPayload();

    const expired = new Date();
    expired.setFullYear(expired.getFullYear() - 1);
    dynamicBloomFilterVC.exp = expired.getTime();
    const verifier = new BloomFilterVerifier({
      vc: dynamicBloomFilterVC,
      timeCheck: true,
    });
    // create the token
    const vcToken = await createCredentialStatusToken(
      credentialStatusVc,
      issuer
    );
    await expect(verifier.isValid(vcToken)).rejects.toThrow(
      'Bloom filter is no longer valid'
    );
  });

  it('revoke a value in the list', async () => {
    const config: DynamicBloomFilterConfig = {
      id: randomUUID(),
      issuer,
    };
    const statuslist = new DynamicBloomFilter(config);
    const id = randomUUID();
    const secret = createSecret();
    await statuslist.addInvalid(id, secret);
    const dynamicBloomFilterVC = statuslist.createVcPayload();

    const verifier = new BloomFilterVerifier({
      vc: dynamicBloomFilterVC,
    });
    const duration = Math.floor(Date.now() / 1000 / DEFAULT_EPOCH);
    const token = await hmac(
      duration.toString(),
      secret,
      statuslist.hmacFunction
    );
    // create a dummy vc because the valid function requires one
    const vc: CredentialStatusToken = {
      exp: 0,
      iat: 0,
      sub: id,
      token,
      iss: '',
    };
    expect(await verifier.isValid(vc)).toBe(false);
  });

  it('load a list from the storage', async () => {
    const config: DynamicBloomFilterConfig = {
      id: randomUUID(),
      issuer,
      epoch: DEFAULT_EPOCH,
      falsePositive: DEFAULT_FALSE_POSITIVE,
      size: 100,
      hashFunction: 'SHA-256',
      hmacFunction: 'SHA-256',
    };
    const entries: VcStatus[] = [];
    for (let i = 0; i < (config.size as number); i++) {
      entries.push({
        s_id: randomUUID(),
        secret: createSecret(),
        valid: i % 2 === 0,
      });
    }
    const statuslist = new DynamicBloomFilter(config);
    for (const entry of entries) {
      entry.valid
        ? statuslist.addValid(entry.s_id, entry.secret)
        : statuslist.addInvalid(entry.s_id, entry.secret);
    }

    const duration = Math.floor(Date.now() / 1000 / DEFAULT_EPOCH);

    for (let i = 0; i < entries.length; i++) {
      const token = await hmac(
        duration.toString(),
        entries[i].secret,
        statuslist.hmacFunction
      );

      const validHash = await hash(
        [token, entries[i].s_id],
        statuslist.hashFunction
      );
      const invalidHash = await hash([validHash], statuslist.hashFunction);

      expect(statuslist.bloomFilter.has(validHash)).toBe(entries[i].valid);
      expect(statuslist.bloomFilter.has(invalidHash)).toBe(!entries[i].valid);
    }
  }, 30000);
});
