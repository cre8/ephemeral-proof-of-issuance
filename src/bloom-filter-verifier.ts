import { BloomFilter } from 'bloom-filters';
import { inflate } from 'pako';
import { DynamicSLBloomFilter2023VC } from './dto/dynamic-sl-bloom-filter-2023';
import { hash, base64Decode } from './util';
import {
  DEFAULT_FALSE_POSITIVE,
  DEFAULT_NBHASHES,
  DEFAULT_SIZE,
} from './const';
import { CredentialStatusToken } from './dto/credential-status-token';

export interface BloomFilterVerifierConfig {
  size?: number;
  falsePositive?: number;
  nbHashes?: number;
  timeCheck?: boolean;
  vc: DynamicSLBloomFilter2023VC;
}

/**
 * Verifier that can be used to verify bloomfilter
 */
export class BloomFilterVerifier {
  // bloom filter used to store the values
  public bloomFilter: BloomFilter;

  // time when the bloom filter is no longer valid
  private validUntil: number;
  timeCheck: boolean;

  /**
   * Iinit the verifier
   * @param config
   */
  constructor(config: BloomFilterVerifierConfig) {
    const size = config.size ?? DEFAULT_SIZE;
    const nbHashes = config.nbHashes ?? DEFAULT_NBHASHES;
    const falsePositive = config.falsePositive ?? DEFAULT_FALSE_POSITIVE;
    this.timeCheck = config.timeCheck ?? false;
    const bloomSize = Math.ceil(
      -((size * Math.log(falsePositive)) / Math.pow(Math.log(2), 2))
    );
    this.bloomFilter = new BloomFilter(bloomSize, nbHashes);
    this.bloomFilter._filter.array = inflate(
      base64Decode(config.vc.credentialSubject.content)
    );
    // we are looking on the validUntil field of the status list credential, not the one we get from the holder.
    this.validUntil = new Date(config.vc.validUntil).getTime();
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
    const validHash = await hash([
      vc.credentialSubject.token,
      vc.credentialSubject.id,
    ]);
    const invalidHash = await hash([validHash]);
    return (
      this.bloomFilter.has(validHash) && !this.bloomFilter.has(invalidHash)
    );
  }
}
