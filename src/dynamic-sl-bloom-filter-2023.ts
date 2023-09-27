import { BloomFilter } from 'bloom-filters';
import { deflate } from 'pako';
import {
  DynamicSLBloomFilter2023VC,
  ListPurpose,
} from './dto/dynamic-sl-bloom-filter-2023';
import { hmac, hash, base64Encode } from './util';
import { CredentialStatusSecretVc } from './dto/credential-status-secret';
import { randomUUID } from 'node:crypto';
import { DynamicSLBloomFilter2023Config } from './dto/dynamic-sl-bloom-filter-2023-config';
import {
  DEFAULT_EPOCH,
  DEFAULT_FALSE_POSITIVE,
  DEFAULT_NBHASHES,
  DEFAULT_SIZE,
} from './const';

export class DynamicSLBloomFilter2023 {
  // id of the status list
  id: string;
  // issuer of the list
  issuer: string;
  // path where the schema is located. Required for the vc-issuer to validate the vc
  dynamicSLBloomFilter2023Schema: string;
  // purpose of the list
  purpose: ListPurpose;
  // posibliity of a false positive event
  falsePositive: number;
  // size of the list
  size: number;
  // number of hash functions used
  nbHashes: number;
  // period in seconds a status list is valid
  epoch: number;

  // bloom filter used to store the values
  public bloomFilter: BloomFilter;
  // Count of the number of durations, where duration is chosen by use case, and t-now is a unix epoch value representing the current time.
  private duration: number;

  constructor(config: DynamicSLBloomFilter2023Config) {
    this.id = config.id;
    this.issuer = config.issuer;
    this.dynamicSLBloomFilter2023Schema = config.dynamicSLBloomFilter2023Schema;
    this.purpose = config.purpose ?? 'revocation';
    this.falsePositive = config.falsePositive ?? DEFAULT_FALSE_POSITIVE;
    this.size = config.size ?? DEFAULT_SIZE;
    this.nbHashes = config.nbHashes ?? DEFAULT_NBHASHES;
    this.epoch = config.epoch ?? DEFAULT_EPOCH;

    const bloomSize = Math.round(
      -(this.size * Math.log(this.falsePositive)) / Math.log(2) ** 2
    );
    this.duration = Math.floor(Date.now() / 1000 / this.epoch);
    this.bloomFilter = new BloomFilter(bloomSize, this.nbHashes);
  }

  /**
   * Adds an entry to the list. Returns an unsigned vc that includes the token
   * @param s_id
   * @param secret
   */
  async addValid(s_id: string, secret: string) {
    // time based password
    const token = await hmac(this.duration.toString(), secret);
    // Status hash to declare validity
    const validHash = await hash(token, s_id);
    this.bloomFilter.add(validHash);
    return this.createStatusVc(secret, s_id);
  }

  /**
   * Creates a vc that includes the token
   * @param secret
   */
  private createStatusVc(
    secret: string,
    s_id: string
  ): CredentialStatusSecretVc {
    return {
      '@context': ['https://www.w3.org/2018/credentials/v1'],
      type: [
        'VerifiableCredential',
        'VerifiableAttestation',
        'CredentialStatusSecret',
      ],
      credentialSubject: {
        duration: this.duration,
        secret,
        id: s_id,
      },
      credentialSchema: {
        type: 'FullJsonSchemaValidator2021',
        id: '',
      },
      issuanceDate: new Date().toISOString(),
      validFrom: new Date().toISOString(),
      issuer: this.issuer,
      id: randomUUID(),
    };
  }

  /**
   * Adds the invalid hash to the list
   * @param s_id
   * @param secret
   */
  async addInvalid(s_id: string, secret: string) {
    // time based password
    const token = await hmac(this.duration.toString(), secret);
    // Status hash to declare validity
    const validHash = await hash(token, s_id);
    const invalidHash = await hash(validHash);
    this.bloomFilter.add(invalidHash);
  }

  /**
   * Creates a JWT that includes the vc
   * @returns
   */
  createVc(): DynamicSLBloomFilter2023VC {
    // gzip and base64 encode the filter
    const filter = base64Encode(deflate(this.bloomFilter._filter.array));
    // create the vc
    const issuanceDate = new Date();
    const expirationDate = new Date();
    expirationDate.setSeconds(expirationDate.getSeconds() + this.epoch);
    return {
      '@context': ['https://www.w3.org/2018/credentials/v1'],
      type: [
        'VerifiableCredential',
        'VerifiableAttestation',
        'DynamicSLBloomFilter2023',
      ],
      id: this.id,
      issuer: this.issuer,
      // we need the lifetime for the vc-issuer, otherwhise the validator will not know that this list is no longer active
      issuanceDate: issuanceDate.toISOString(),
      expirationDate: expirationDate.toISOString(),
      validFrom: issuanceDate.toISOString(),
      validUntil: expirationDate.toISOString(),
      credentialSubject: {
        // not clear why we need the fragment here. Can maybe be removed
        id: `${this.id}#list`,
        purpose: this.purpose,
        content: filter,
      },
      credentialSchema: {
        id: this.dynamicSLBloomFilter2023Schema,
        type: 'FullJsonSchemaValidator2021',
      },
    };
  }
}
