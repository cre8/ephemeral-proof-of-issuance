import BloomFilter from 'bloom-filters';
import { inflate } from 'pako';
import type { CredentialStatusToken } from '../dto/credential-status-token.js';
import { base64Decode, hash } from '../util.js';
import { Verifier } from './verifier.js';
import { VerifierConfig } from '../dto/verifier-config.js';
import { DynamicBloomFilterVC } from '../dto/dynamic-bloom-filter.js';

/**
 * Verifier that can be used to verify bloomfilter
 */
export class BloomFilterVerifier extends Verifier {
  // bloom filter used to store the values
  public bloomFilter: BloomFilter.BloomFilter;

  /**
   * Iinit the verifier
   * @param config
   */
  constructor(config: VerifierConfig<DynamicBloomFilterVC>) {
    super(config);

    const size = config.vc.size;
    const falsePositive = config.vc.falsePositive;
    this.bloomFilter = BloomFilter.BloomFilter.create(size, falsePositive);
    this.bloomFilter._filter.array = inflate(base64Decode(config.vc.content));
  }

  /**
   * Checks if the valid value is included and the invalid is not included
   * @param vc
   * @returns
   */
  async isValid(vc: CredentialStatusToken) {
    if (this.timeCheck && this.validUntil < Date.now())
      throw new Error('Bloom filter is no longer valid');
    // TODO validate the signature of the vc
    const validHash = await hash([vc.token, vc.sub], this.hashFunction);
    const invalidHash = await hash([validHash], this.hashFunction);
    return (
      this.bloomFilter.has(validHash) && !this.bloomFilter.has(invalidHash)
    );
  }
}
