import { describe, it, beforeAll, expect } from 'vitest';
import { randomUUID } from 'crypto';
import { DynamicSLBloomFilter } from '../dynamic-sl-bloom-filter.js';
import { VcStatus } from '../dto/vc-status.js';
import { DynamicSLBloomFilterConfig } from '../dto/dynamic-sl-bloom-filter-config.js';
import { createSecret, hash, hmac } from '../util.js';
import { BloomFilterVerifier } from '../bloom-filter-verifier.js';
import { createCredentialStatusToken } from '../holder.js';
import {
  DEFAULT_SIZE,
  DEFAULT_FALSE_POSITIVE,
  DEFAULT_NBHASHES,
  DEFAULT_EPOCH,
} from '../const.js';
import { CredentialStatusToken } from '../dto/credential-status-token.js';

// issuer reference of the vc statuslist
const issuer = 'did:web:exmaple.com';

// path where the schema is located. Required for the vc-issuer to validate the vc
const dynamicSLBloomFilterSchema = 'pathToTheSchema';

async function init() {}

describe('bloom list', () => {
  beforeAll(async () => {
    await init();
  });

  it('creates a list', () => {
    const config: DynamicSLBloomFilterConfig = {
      dynamicSLBloomFilterSchema,
      id: randomUUID(),
      issuer,
      epoch: DEFAULT_EPOCH,
      falsePositive: DEFAULT_FALSE_POSITIVE,
      nbHashes: DEFAULT_NBHASHES,
      purpose: 'revocation',
      size: DEFAULT_SIZE,
      hashFunction: 'SHA-256',
      hmacFunction: 'SHA-256',
    };
    const statuslist = new DynamicSLBloomFilter(config);
    expect(statuslist).toBeDefined();
  });
  //TODO: move this to a benchmark test, since this is not a unit test
  it('is a value in the list', async () => {
    const config: DynamicSLBloomFilterConfig = {
      dynamicSLBloomFilterSchema,
      id: randomUUID(),
      issuer,
      hashFunction: 'SHA-256',
      hmacFunction: 'SHA-256',
    };
    const statuslist = new DynamicSLBloomFilter(config);
    const id = randomUUID();
    const secret = createSecret();
    const credentialStatusVc = await statuslist.addValid(id, secret);
    const dynamicSLBloomFilterVC = statuslist.createVc();

    const verifier = new BloomFilterVerifier({
      vc: dynamicSLBloomFilterVC,
    });
    // create the token
    const holderDid = 'did:web:holder.example.com';
    const vcToken = await createCredentialStatusToken(
      credentialStatusVc,
      holderDid
    );
    expect(await verifier.isValid(vcToken)).toBe(true);

    vcToken.credentialSubject.token = 'invalidValue';
    expect(await verifier.isValid(vcToken)).toBe(false);
  });

  it('check with an expired vc', async () => {
    const config: DynamicSLBloomFilterConfig = {
      dynamicSLBloomFilterSchema,
      id: randomUUID(),
      issuer,
      hashFunction: 'SHA-256',
      hmacFunction: 'SHA-256',
    };
    const statuslist = new DynamicSLBloomFilter(config);
    const id = randomUUID();
    const secret = createSecret();
    const credentialStatusVc = await statuslist.addValid(id, secret);
    const dynamicSLBloomFilterVC = statuslist.createVc();

    const expired = new Date();
    expired.setFullYear(expired.getFullYear() - 1);
    dynamicSLBloomFilterVC.validUntil = expired.toISOString();
    const verifier = new BloomFilterVerifier({
      vc: dynamicSLBloomFilterVC,
      timeCheck: true,
      size: DEFAULT_SIZE,
      falsePositive: DEFAULT_FALSE_POSITIVE,
      nbHashes: DEFAULT_NBHASHES,
    });
    // create the token
    const holderDid = 'did:web:holder.example.com';
    const vcToken = await createCredentialStatusToken(
      credentialStatusVc,
      holderDid
    );
    await expect(verifier.isValid(vcToken)).rejects.toThrow(
      'Bloom filter is no longer valid'
    );
  });

  it('revoke a value in the list', async () => {
    const config: DynamicSLBloomFilterConfig = {
      dynamicSLBloomFilterSchema,
      id: randomUUID(),
      issuer,
      hashFunction: 'SHA-256',
      hmacFunction: 'SHA-256',
    };
    const statuslist = new DynamicSLBloomFilter(config);
    const id = randomUUID();
    const secret = createSecret();
    await statuslist.addInvalid(id, secret);
    const dynamicSLBloomFilterVC = statuslist.createVc();

    const verifier = new BloomFilterVerifier({
      vc: dynamicSLBloomFilterVC,
    });
    const duration = Math.floor(Date.now() / 1000 / DEFAULT_EPOCH);
    const token = await hmac(duration.toString(), secret, config.hmacFunction);
    // create a dummy vc because the valid function requires one
    const vc: CredentialStatusToken = {
      '@context': ['https://www.w3.org/2018/credentials/v1'],
      type: [
        'VerifiableCredential',
        'VerifiableAttestation',
        'CredentialStatusToken',
      ],
      credentialSchema: {
        id: '',
        type: 'FullJsonSchemaValidator2021',
      },
      expirationDate: '',
      credentialSubject: {
        id,
        token,
      },
      issuanceDate: '',
      validUntil: '',
      id: '',
      issuer: '',
      validFrom: '',
    };
    expect(await verifier.isValid(vc)).toBe(false);
  });

  it('load a list from the storage', async () => {
    const config: DynamicSLBloomFilterConfig = {
      dynamicSLBloomFilterSchema,
      id: randomUUID(),
      issuer,
      epoch: DEFAULT_EPOCH,
      falsePositive: DEFAULT_FALSE_POSITIVE,
      nbHashes: DEFAULT_NBHASHES,
      purpose: 'revocation',
      size: 100,
      hashFunction: 'SHA-256',
      hmacFunction: 'SHA-256',
    };
    const entries: VcStatus[] = [];
    for (let i = 0; i < config.size!; i++) {
      entries.push({
        s_id: randomUUID(),
        secret: createSecret(),
        valid: false,
      });
    }
    const statuslist = await DynamicSLBloomFilter.addByWorker(
      config,
      entries,
      1
    );

    const duration = Math.floor(Date.now() / 1000 / DEFAULT_EPOCH);
    const token = await hmac(
      duration.toString(),
      entries[0].secret,
      config.hmacFunction
    );
    const validHash = await hash([token, entries[0].s_id], config.hashFunction);
    const invalidHash = await hash([validHash], config.hashFunction);

    expect(statuslist.bloomFilter.has(validHash)).toBe(entries[0].valid);
    expect(statuslist.bloomFilter.has(invalidHash)).toBe(!entries[0].valid);
  }, 30000);
});
