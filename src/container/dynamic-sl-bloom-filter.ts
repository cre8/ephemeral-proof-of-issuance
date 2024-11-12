import BloomFilter from 'bloom-filters';
import { deflate } from 'pako';
import { DEFAULT_FALSE_POSITIVE, DEFAULT_SIZE } from '../const.js';
import type { DynamicSLBloomFilterConfig } from '../dto/dynamic-sl-bloom-filter-config.js';
import type { DynamicSLBloomFilterVC } from '../dto/dynamic-sl-bloom-filter.js';
import { base64Encode, hash } from '../util.js';
import { Container } from './container.js';

/**
 * A dynamic status list based on a bloom filter.
 */
export class DynamicSLBloomFilter extends Container {
  // posibliity of a false positive event
  private falsePositive: number;
  // size of the list
  private size: number;

  // bloom filter used to store the values
  public bloomFilter: BloomFilter.BloomFilter;

  constructor(config: DynamicSLBloomFilterConfig) {
    super(config);
    this.falsePositive = config.falsePositive ?? DEFAULT_FALSE_POSITIVE;
    this.size = config.size ?? DEFAULT_SIZE;
    //the bloomfilter can be created by either size and falsepositive, or by bit size and hash functions
    this.bloomFilter = BloomFilter.BloomFilter.create(
      this.size,
      this.falsePositive
    );
  }

  /**
   * Adds an entry to the list. Returns an unsigned vc that includes the token.
   * @param s_id The id of the entry
   * @param secret The secret of the entry
   */
  async addValid(s_id: string, secret: string) {
    const validHash = await this.calculateValidHash(secret, s_id);
    this.bloomFilter.add(validHash);
    return this.createStatusVcPayload(secret, s_id);
  }

  /**
   * Adds the invalid hash to the list
   * @param s_id id of the vc
   * @param secret secret of the vc
   */
  async addInvalid(s_id: string, secret: string) {
    // Status hash to declare validity
    const validHash = await this.calculateValidHash(secret, s_id);
    const invalidHash = await hash([validHash], this.hashFunction);
    this.bloomFilter.add(invalidHash);
  }

  /**
   * Creates an unsigned VC that includes the filter.
   * @returns unsigned payload
   */
  createVcPayload(): DynamicSLBloomFilterVC {
    // gzip and base64 encode the filter
    const filter = base64Encode(deflate(this.bloomFilter._filter.array));
    // create the vc
    const issuanceDate = new Date();
    const expirationDate = new Date();
    expirationDate.setSeconds(expirationDate.getSeconds() + this.epoch);
    return {
      jti: this.id,
      iss: this.issuer,
      // we need the lifetime for the vc-issuer, otherwhise the validator will not know that this list is no longer active
      iat: issuanceDate.getTime(),
      exp: expirationDate.getTime(),
      content: filter,
      hashFunction: this.hashFunction,
      falsePositive: this.falsePositive,
      size: this.size,
    };
  }
}
