import BloomFilter from 'bloom-filters';
import { inflate } from 'pako';
import type { CredentialStatusToken } from '../dto/credential-status-token.js';
import { base64Decode, hash } from '../util.js';
import { Verifier } from './verifier.js';
import { VerifierConfig } from '../dto/verifier-config.js';
import { DynamicCascadingBloomFilterVC } from '../dto/dynamic-cascading-bloom-filter.js';

/**
 * Verifier that can be used to verify bloomfilter
 */
export class CascadingBloomFilterVerifier extends Verifier {
  // bloom filter used to store the values
  public bloomFilters: BloomFilter.BloomFilter[];

  /**
   * Iinit the verifier
   * @param config
   */
  constructor(config: VerifierConfig<DynamicCascadingBloomFilterVC>) {
    super(config);

    const size = config.vc.size;
    const falsePositive = config.vc.falsePositive;
    this.bloomFilters = config.vc.content.map((content) => {
      const bloomFilter = BloomFilter.BloomFilter.create(size, falsePositive);
      bloomFilter._filter.array = inflate(base64Decode(content));
      return bloomFilter;
    });
  }

  /**
   * Checks if the valid value is included and the invalid is not included
   * @param vc
   * @returns
   */
  async isValid(vc: CredentialStatusToken) {
    const filter = 0;
    if (this.timeCheck && this.validUntil < Date.now())
      throw new Error('Bloom filter is no longer valid');
    // TODO validate the signature of the vc
    const validHash = await hash([vc.token, vc.sub], this.hashFunction);
    const invalidHash = await hash([validHash], this.hashFunction);
    //TODO: need to check for false positive events
    if (this.bloomFilters[filter].has(validHash)) {
      // check next filter
      if (!this.bloomFilters[filter + 1].has(validHash)) {
      } else {
      }
    } else {
      // valid is not included, so it should be invalid or not managed by it at all
    }
    return (
      this.bloomFilters[filter].has(validHash) &&
      !this.bloomFilters[filter].has(invalidHash)
    );
  }
}
