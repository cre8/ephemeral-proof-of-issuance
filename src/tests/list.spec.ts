import { randomUUID } from 'node:crypto';
import { beforeAll, describe, expect, it } from 'vitest';
import { DEFAULT_EPOCH } from '../const.js';
import { DynamicList } from '../container/dynamic-list.js';
import type { ContainerConfig } from '../dto/container-config.js';
import type { CredentialStatusTokenPayload } from '../dto/credential-status-token-payload.js';
import type { VcStatus } from '../dto/vc-status.js';
import { createCredentialStatusToken } from '../holder.js';
import { createSecret, hash, hmac } from '../util.js';
import { ClVerifier } from '../verifier/cl-verifier.js';

// issuer reference of the vc statuslist
const issuer = 'http://example.com';

async function init() {}

describe('list', () => {
  beforeAll(async () => {
    await init();
  });

  /*   it('creates a list', () => {
    const config: ContainerConfig = {
      id: randomUUID(),
      issuer,
      epoch: DEFAULT_EPOCH,
    };
    const statuslist = new DynamicCL(config);
    expect(statuslist).toBeDefined();
  }); */

  it('is a value in the list', async () => {
    const config: ContainerConfig = {
      id: randomUUID(),
      issuer,
    };
    const statuslist = new DynamicList(config);
    const id = randomUUID();
    const secret = createSecret();
    const credentialStatusVc = await statuslist.addValid(id, secret);
    const dynamicCRLVC = statuslist.createVcPayload();

    const verifier = new ClVerifier({
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
    const statuslist = new DynamicList(config);
    const id = randomUUID();
    const secret = createSecret();
    const credentialStatusVc = await statuslist.addValid(id, secret);
    const dynamicBloomFilterVC = statuslist.createVcPayload();

    const expired = new Date();
    expired.setFullYear(expired.getFullYear() - 1);
    dynamicBloomFilterVC.exp = expired.getTime();
    const verifier = new ClVerifier({
      vc: dynamicBloomFilterVC,
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
    const statuslist = new DynamicList(config);
    const id = randomUUID();
    const secret = createSecret();
    await statuslist.addInvalid(id, secret);
    const dynamicBloomFilterVC = statuslist.createVcPayload();

    const verifier = new ClVerifier({
      vc: dynamicBloomFilterVC,
    });
    const duration = Math.floor(Date.now() / 1000 / DEFAULT_EPOCH);
    const token = await hmac(
      duration.toString(),
      secret,
      statuslist.hmacFunction
    );
    // create a dummy vc because the valid function requires one
    const vc: CredentialStatusTokenPayload = {
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
    for (let i = 0; i < 10; i++) {
      entries.push({
        s_id: randomUUID(),
        secret: createSecret(),
        valid: i % 2 === 0,
      });
    }
    const statuslist = new DynamicList(config);
    for (const entry of entries) {
      if (entry.valid) {
        statuslist.addValid(entry.s_id, entry.secret);
      }
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

      expect(statuslist.entries.has(validHash)).toBe(entries[i].valid);
    }
  }, 30000);
});
