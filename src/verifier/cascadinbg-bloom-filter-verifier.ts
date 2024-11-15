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
    if (this.timeCheck && this.validUntil < Date.now())
      throw new Error('Bloom filter is no longer valid');
    //TODO: validate the signature of the vc
    const validHash = await hash([vc.token, vc.sub], this.hashFunction);
    // if the filter is even, the valid hash should not be included, if odd it should be included
    for (let filter = 0; filter < this.bloomFilters.length; filter++) {
      if (filter % 2 === 0) {
        console.log(1);
        // it is not included in the filter, therefore it was not inserted and it is not valid
        if (!this.bloomFilters[filter].has(validHash)) {
          return false;
        } else if (filter === this.bloomFilters.length - 1) {
          return true;
        }
        // else could be false positive, we need to check the next filter
      } else {
        console.log(2);
        if (!this.bloomFilters[filter].has(validHash)) {
          //TODO: a wrong value is NEVER included in the second filter, it it will return true here...
          return true;
        } else if (filter === this.bloomFilters.length - 1) {
          return false;
        }
      }
    }
    throw Error('Should not reach this point');
  }
}
