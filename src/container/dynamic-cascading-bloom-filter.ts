import BloomFilter from 'bloom-filters';
import { deflate } from 'pako';
import { DEFAULT_FALSE_POSITIVE, DEFAULT_SIZE } from '../const.js';
import { base64Encode, hash } from '../util.js';
import { Container } from './container.js';
import { DynamicCascadingBloomFilterVC } from '../dto/dynamic-cascading-bloom-filter.js';
import { DynamicCascadingBloomFilterConfig } from '../dto/dynamic-cascading-bloom-filter-config.js';

/**
 * A dynamic status list based on a bloom filter.
 */
export class DynamicCascadingBloomFilter extends Container {
  // posibliity of a false positive event
  private falsePositive: number;
  // size of the list
  private size: number;

  private cachHashes: boolean;

  // save the invalid value of the valid hashed to check for false positive events since they should not be included in the first filter
  private invalidOfValidHashes: Set<string> = new Set();

  // save the invalid hashes to check that they are not included in the next filter
  private invalidHashes: Set<string> = new Set();

  // bloom filter used to store the values
  public bloomFilters: BloomFilter.BloomFilter[] = [];

  private rounds = 0;

  constructor(config: DynamicCascadingBloomFilterConfig) {
    super(config);
    this.falsePositive = config.falsePositive ?? DEFAULT_FALSE_POSITIVE;
    this.size = config.size ?? DEFAULT_SIZE;
    this.cachHashes = config.cacheHashed ?? false;
    //the bloomfilter can be created by either size and falsepositive, or by bit size and hash functions
    this.bloomFilters.push(this.createFilter());
  }

  private createFilter() {
    return BloomFilter.BloomFilter.create(this.size, this.falsePositive);
  }

  /**
   * Adds an entry to the list. Returns an unsigned vc that includes the token.
   * @param s_id The id of the entry
   * @param secret The secret of the entry
   */
  async addValid(s_id: string, secret: string) {
    const validHash = await this.calculateValidHash(secret, s_id);
    this.bloomFilters[0].add(validHash);

    //add the hash to the list
    if (this.cachHashes) {
      const invalidHash = await hash([validHash], this.hashFunction);
      this.invalidOfValidHashes.add(invalidHash);
    }
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
    // remove the element in case it was added before
    if (this.cachHashes && this.invalidOfValidHashes.has(validHash)) {
      // will never be called right now
      this.invalidOfValidHashes.delete(validHash);
    }
    const invalidHash = await hash([validHash], this.hashFunction);
    // add it to the list to compare against the next filter
    this.invalidHashes.add(invalidHash);
    this.bloomFilters[0].add(invalidHash);
  }

  /**
   * Check if cascading filters are needed to eliminate false positives, building them recursively.
   */
  private async buildCascadingFilter() {
    this.rounds++;
    if (this.rounds > 5) {
      console.log('Max rounds reached');
      return;
    }
    const currentFilter = this.bloomFilters[this.bloomFilters.length - 1];
    let newFilter = this.createFilter();
    let filterCreated = false;

    // Process valid-but-false-positive entries (invalidOfValidHashes) for the current filter
    for (const hashValue of this.invalidOfValidHashes) {
      if (currentFilter.has(hashValue)) {
        filterCreated = true;
        newFilter.add(hashValue);
      }
    }

    // when we found false positive cases, we need to add the bloom filter and check for more false positive cases
    if (filterCreated) {
      this.bloomFilters.push(newFilter);
      newFilter = this.createFilter();
      // Verify that invalid hashes are not incorrectly marked as included in the new filter
      const falsePositivesInNewFilter = new Set<string>();
      for (const invalidHash of this.invalidHashes) {
        if (newFilter.has(invalidHash)) {
          falsePositivesInNewFilter.add(invalidHash);
        }
        newFilter.add(invalidHash); // Add all invalid hashes to filter
      }
      this.bloomFilters.push(newFilter);

      // If there are still false positives after adding invalid entries, recursively create a new filter
      if (falsePositivesInNewFilter.size > 0) {
        console.log('run');
        console.log(this.invalidOfValidHashes);
        await this.buildCascadingFilter(); // Recursive call
      }
    }
  }

  /**
   * Creates an unsigned VC that includes the filter.
   * @returns unsigned payload
   */
  async createVcPayload(): Promise<DynamicCascadingBloomFilterVC> {
    this.rounds = 0;
    await this.buildCascadingFilter();

    // gzip and base64 encode the filter
    const filters = this.bloomFilters.map((bloomfilter) =>
      base64Encode(deflate(bloomfilter._filter.array))
    );
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
      content: filters,
      hashFunction: this.hashFunction,
      falsePositive: this.falsePositive,
      size: this.size,
    };
  }
}
