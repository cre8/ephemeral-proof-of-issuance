import BloomFilter from 'bloom-filters';
import { inflate } from 'pako';
import { hash, base64Decode, HashFunctionName } from './util.js';
import { CredentialStatusToken } from './dto/credential-status-token.js';
import { BloomFilterVerifierConfig } from './dto/bloom-filter-verifier-config.js';

/**
 * Verifier that can be used to verify bloomfilter
 */
export class BloomFilterVerifier {
  // bloom filter used to store the values
  public bloomFilter: BloomFilter.BloomFilter;

  // time when the bloom filter is no longer valid
  private validUntil: number;
  timeCheck: boolean;
  hashFunctions: HashFunctionName[];

  /**
   * Iinit the verifier
   * @param config
   */
  constructor(config: BloomFilterVerifierConfig) {
    const size = config.vc.credentialSubject.size;
    const falsePositive = config.vc.credentialSubject.falsePositive;
    this.timeCheck = config.timeCheck ?? false;
    this.bloomFilter = BloomFilter.BloomFilter.create(size, falsePositive);
    this.bloomFilter._filter.array = inflate(
      base64Decode(config.vc.credentialSubject.content)
    );
    // we are looking on the validUntil field of the status list credential, not the one we get from the holder.
    this.validUntil = new Date(config.vc.validUntil).getTime();
    if (Array.isArray(config.vc.credentialSubject.hashFunction)) {
      this.hashFunctions = config.vc.credentialSubject.hashFunction;
    } else {
      this.hashFunctions = [config.vc.credentialSubject.hashFunction];
    }
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
    const validHash = await hash(
      [vc.credentialSubject.token, vc.credentialSubject.id],
      this.hashFunctions[0]
    );
    const invalidHash = await hash([validHash], this.hashFunctions[0]);
    return (
      this.bloomFilter.has(validHash) && !this.bloomFilter.has(invalidHash)
    );
  }
}
