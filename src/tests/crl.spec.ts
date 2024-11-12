import { randomUUID } from 'node:crypto';
import { beforeAll, describe, expect, it } from 'vitest';
import { DEFAULT_EPOCH, DEFAULT_FALSE_POSITIVE } from '../const.js';
import type { CredentialStatusToken } from '../dto/credential-status-token.js';
import type { VcStatus } from '../dto/vc-status.js';
import { createCredentialStatusToken } from '../holder.js';
import { createSecret, hash, hmac } from '../util.js';
import { DynamicCRL } from '../container/dynamic-crl.js';
import { ContainerConfig } from '../dto/container-config.js';
import { CrlVerifier } from '../verifier/crl-verifier copy.js';

// issuer reference of the vc statuslist
const issuer = 'http://example.com';

async function init() {}

describe('crl', () => {
  beforeAll(async () => {
    await init();
  });

  it('creates a list', () => {
    const config: ContainerConfig = {
      id: randomUUID(),
      issuer,
      epoch: DEFAULT_EPOCH,
    };
    const statuslist = new DynamicCRL(config);
    expect(statuslist).toBeDefined();
  });
  it('is a value in the list', async () => {
    const config: ContainerConfig = {
      id: randomUUID(),
      issuer,
    };
    const statuslist = new DynamicCRL(config);
    const id = randomUUID();
    const secret = createSecret();
    const credentialStatusVc = await statuslist.addValid(id, secret);
    const dynamicCRLVC = statuslist.createVcPayload();

    const verifier = new CrlVerifier({
      vc: dynamicCRLVC,
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
    const config: ContainerConfig = {
      id: randomUUID(),
      issuer,
      hashFunction: 'SHA-256',
      hmacFunction: 'SHA-256',
    };
    const statuslist = new DynamicCRL(config);
    const id = randomUUID();
    const secret = createSecret();
    const credentialStatusVc = await statuslist.addValid(id, secret);
    const dynamicSLBloomFilterVC = statuslist.createVcPayload();

    const expired = new Date();
    expired.setFullYear(expired.getFullYear() - 1);
    dynamicSLBloomFilterVC.exp = expired.getTime();
    const verifier = new CrlVerifier({
      vc: dynamicSLBloomFilterVC,
      timeCheck: true,
    });
    // create the token
    const vcToken = await createCredentialStatusToken(
      credentialStatusVc,
      issuer
    );
    await expect(verifier.isValid(vcToken)).rejects.toThrow(
      'CRL is no longer valid'
    );
  });

  it('revoke a value in the list', async () => {
    const config: ContainerConfig = {
      id: randomUUID(),
      issuer,
    };
    const statuslist = new DynamicCRL(config);
    const id = randomUUID();
    const secret = createSecret();
    await statuslist.addInvalid(id, secret);
    const dynamicSLBloomFilterVC = statuslist.createVcPayload();

    const verifier = new CrlVerifier({
      vc: dynamicSLBloomFilterVC,
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
    const config: ContainerConfig = {
      id: randomUUID(),
      issuer,
      epoch: DEFAULT_EPOCH,
      hashFunction: 'SHA-256',
      hmacFunction: 'SHA-256',
    };
    const entries: VcStatus[] = [];
    for (let i = 0; i < 100; i++) {
      entries.push({
        s_id: randomUUID(),
        secret: createSecret(),
        valid: i % 2 === 0,
      });
    }
    const statuslist = new DynamicCRL(config);
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

      expect(statuslist.entries.has(validHash)).toBe(entries[i].valid);
      expect(statuslist.entries.has(invalidHash)).toBe(!entries[i].valid);
    }
  }, 30000);
});
