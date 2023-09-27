// __tests__/utils.test.ts

import { randomUUID } from 'crypto';
import { existsSync, mkdirSync, readFileSync, stat, writeFileSync } from 'fs';
import { SignJWT, exportJWK, generateKeyPair } from 'jose';
import { DynamicSLBloomFilter2023 } from '../dynamic-sl-bloom-filter-2023';
import { DynamicSLBloomFilter2023Config } from '../dto/dynamic-sl-bloom-filter-2023-config';
import { createSecret, signVc } from '../util';
import { BloomFilterVerifier } from '../bloom-filter-verifier';
import { createCredentialStatusToken } from '../holder';

// paths where the key pair is stored
const privateKeyPath = 'tmp/jwk.private.json';
const publicKeyPath = 'tmp/jwk.public.json';

// issuer reference of the vc statuslist
const issuer = 'did:web:exmaple.com';

// algorithm used to sign the vc
const alg = 'ES256';

// path where the schema is located. Required for the vc-issuer to validate the vc
const dynamicSLBloomFilter2023Schema = 'pathToTheSchema';

/**
 * Creates the key pair if it does not exist.
 */
async function init() {
  if (!existsSync('tmp')) {
    mkdirSync('tmp');
  }
  if (!existsSync(privateKeyPath) || !existsSync(publicKeyPath)) {
    const { privateKey, publicKey } = await generateKeyPair(alg);
    writeFileSync(privateKeyPath, JSON.stringify(await exportJWK(privateKey)));
    writeFileSync(publicKeyPath, JSON.stringify(await exportJWK(publicKey)));
  }
}

function getPrivateKey() {
  return JSON.parse(readFileSync(privateKeyPath, 'utf-8'));
}

describe('bloom list 2023', () => {
  beforeAll(async () => {
    await init();
  });

  it('creates a list', () => {
    const config: DynamicSLBloomFilter2023Config = {
      dynamicSLBloomFilter2023Schema,
      id: randomUUID(),
      issuer,
    };
    const statuslist = new DynamicSLBloomFilter2023(config);
    expect(statuslist).toBeDefined();
  });
  it('is a value in the list', async () => {
    const config: DynamicSLBloomFilter2023Config = {
      dynamicSLBloomFilter2023Schema,
      id: randomUUID(),
      issuer,
    };
    const statuslist = new DynamicSLBloomFilter2023(config);
    const id = randomUUID();
    const secret = createSecret();
    const credentialStatusVc = await statuslist.addValid(id, secret);
    const dynamicSLBloomFilter2023VC = statuslist.createVc();

    const verifier = new BloomFilterVerifier({
      vc: dynamicSLBloomFilter2023VC,
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

  it('revoce a value in the list', () => {});
});
