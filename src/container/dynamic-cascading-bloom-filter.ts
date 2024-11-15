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

  private validHashes: Set<string> = new Set();

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
    this.validHashes.add(validHash);
    this.invalidHashes.delete(validHash);
    return this.createStatusVcPayload(secret, s_id);
  }

  /**
   * Adds the invalid hash to the list. Remove it from the valid list.
   * @param s_id id of the vc
   * @param secret secret of the vc
   */
  async addInvalid(s_id: string, secret: string) {
    // Status hash to declare validity
    const validHash = await this.calculateValidHash(secret, s_id);
    // we save the hash of an invalid one to proof against false positive events
    this.invalidHashes.add(validHash);
    this.validHashes.delete(validHash);
  }

  /**
   * Check if cascading filters are needed to eliminate false positives, building them recursively.
   */
  private async buildCascadingFilter() {
    //reference: https://youtu.be/CZpqKvYyd9k?si=HDov8YwaHdbjaLey&t=556
    this.rounds++;
    if (this.rounds > 5) {
      console.log('Max rounds reached');
      return;
    }
    let currentFilter = this.bloomFilters[this.bloomFilters.length - 1];
    let newFilter = this.createFilter();
    let filterCreated = 0;

    // we need to check for false positive events: no revoked hash should be included in the new filter
    for (const hashValue of this.invalidHashes) {
      if (currentFilter.has(hashValue)) {
        // we found a false positive event, so we need to add it to the new filter
        filterCreated++;
        newFilter.add(hashValue);
      }
    }

    // when we found false positive cases, we need to add the bloom filter and check for more false positive cases
    if (filterCreated > 0) {
      this.bloomFilters.push(newFilter);
      console.log('filter', this.bloomFilters.length - 1, ':', filterCreated);
      currentFilter = this.bloomFilters[this.bloomFilters.length - 1];
      newFilter = this.createFilter();
      filterCreated = 0;
      // iterate over all valid hashes to make sure they are not included in the new filter
      for (const hashValue of this.validHashes) {
        if (currentFilter.has(hashValue)) {
          console.log('false positive found');
          // again we found a false positive event, so we need to add it to the new filter
          filterCreated++;
          newFilter.add(hashValue); // Add all invalid hashes to filter
        }
      }
      // If there are still false positives after adding invalid entries, recursively create a new filter
      if (filterCreated > 0) {
        this.bloomFilters.push(newFilter);
        console.log('filter', this.bloomFilters.length - 1, ':', filterCreated);
        await this.buildCascadingFilter(); // Recursive call
      } else {
        console.log('No false positives found');
      }
    }
  }

  /**
   * Creates an unsigned VC that includes the filter.
   * @returns unsigned payload
   */
  async createVcPayload(): Promise<DynamicCascadingBloomFilterVC> {
    // build up the first filter
    this.validHashes.forEach((validHash) =>
      this.bloomFilters[0].add(validHash)
    );
    console.log('filter 0:', this.validHashes.size);
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
